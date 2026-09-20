import pytest
import pandas as pd
import asyncio
import numpy as np
from unittest.mock import patch, AsyncMock

import backend.main as main_module

class StopLoopException(BaseException):
    pass

@pytest.mark.asyncio
async def test_bucket_finalization_and_quiet_traffic():
    main_module._live_state = None 
    
    mock_redis = AsyncMock()
    call_count = 0
    original_now = pd.Timestamp.now
    original_now = pd.Timestamp.now
    
    async def mock_xread(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return [ ("cic:flows:stream", [("1000-0", {"timestamp": "2026-09-20 20:22:49", "srcport": "1234", "dstport": "80"})]) ]
        elif call_count == 2:
            return []
        else:
            raise StopLoopException("Stop loop")
            
    mock_redis.xread = mock_xread
    mock_redis.xinfo_stream = AsyncMock(return_value={"last-generated-id": "0-0"})
    
    now_times = [
        pd.Timestamp("2026-09-20 20:22:50"), 
        pd.Timestamp("2026-09-20 20:22:50"), 
        pd.Timestamp("2026-09-20 20:22:50"), 
        pd.Timestamp("2026-09-20 20:23:10"), 
        pd.Timestamp("2026-09-20 20:23:10"), 
        pd.Timestamp("2026-09-20 20:23:10"), 
        pd.Timestamp("2026-09-20 20:23:10"),
    ]
    
    def mock_now():
        if now_times:
            return now_times.pop(0)
        return original_now()
        
    with patch("redis.asyncio.Redis", return_value=mock_redis), \
         patch("backend.main.pd.Timestamp.now", side_effect=mock_now), \
         patch("backend.main._model", True), \
         patch("backend.main._aggregate_windows") as mock_agg, \
         patch("backend.main._run_model_inference") as mock_inf:
             
        def mock_aggregate(df):
            return (np.array(["state_data"]), [pd.Timestamp("2026-09-20 20:22:00")], [1], [])
        mock_agg.side_effect = mock_aggregate
        mock_inf.return_value = [{'timestamp': '20:22:00', 'is_warmup': True}]
        try:
            await main_module.redis_stream_consumer()
        except StopLoopException:
            pass
            
    state = main_module._live_state
    assert state["metadata"]["warmup_count"] == 1
    assert len(state["windows"]) == 1
    assert state["windows"][0]["timestamp"] == "20:22:00"

@pytest.mark.asyncio
async def test_sparse_traffic_quiet_status():
    main_module._live_state = None
    mock_redis = AsyncMock()
    call_count = 0
    original_now = pd.Timestamp.now
    
    async def mock_xread(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return [ ("cic:flows", [("1", {"timestamp": "2026-09-20 20:22:00"})]) ]
        elif call_count == 2:
            return []
        else:
            raise StopLoopException()
            
    mock_redis.xread = mock_xread
    mock_redis.xinfo_stream = AsyncMock(return_value={"last-generated-id": "0-0"})
    
    now_times = [
        pd.Timestamp("2026-09-20 20:22:01"),
        pd.Timestamp("2026-09-20 20:22:01"),
        pd.Timestamp("2026-09-20 20:22:01"),
        pd.Timestamp("2026-09-20 20:25:00"), 
        pd.Timestamp("2026-09-20 20:25:00"),
        pd.Timestamp("2026-09-20 20:25:00"),
    ]
    
    def mock_now():
        if now_times: return now_times.pop(0)
        return original_now()
        
    with patch("redis.asyncio.Redis", return_value=mock_redis), \
         patch("backend.main.pd.Timestamp.now", side_effect=mock_now), \
         patch("backend.main._model", True), \
         patch("backend.main._aggregate_windows", return_value=([], [], [], [])):
         
        try:
            await main_module.redis_stream_consumer()
        except StopLoopException:
            pass
            
    assert main_module._live_state["metadata"]["telemetry_status"] in ("QUIET", "WARMING_UP")
    assert main_module._live_state["metadata"]["telemetry_lag_seconds"] >= 120

@pytest.mark.asyncio
async def test_genuine_stale_disconnected():
    main_module._live_state = None
    mock_redis = AsyncMock()
    call_count = 0
    original_now = pd.Timestamp.now
    
    async def mock_xread(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return [ ("cic:flows", [("1", {"timestamp": "2026-09-20 20:22:00"})]) ]
        elif call_count == 2:
            raise Exception("Redis dead")
        elif call_count == 3:
            raise StopLoopException()
            
    mock_redis.xread = mock_xread
    mock_redis.xinfo_stream = AsyncMock(return_value={"last-generated-id": "0-0"})
    
    now_times = [
        pd.Timestamp("2026-09-20 20:22:01"),
        pd.Timestamp("2026-09-20 20:22:01"),
        pd.Timestamp("2026-09-20 20:22:01"), 
        pd.Timestamp("2026-09-20 20:25:00"), # advance > 120s
        pd.Timestamp("2026-09-20 20:25:00"),
    ]
    
    def mock_now():
        if now_times: return now_times.pop(0)
        return original_now()
        
    with patch("redis.asyncio.Redis", return_value=mock_redis), \
         patch("backend.main.pd.Timestamp.now", side_effect=mock_now), \
         patch("backend.main._model", True), \
         patch("backend.main._aggregate_windows", return_value=([], [], [], [])), \
         patch("backend.main.asyncio.sleep", AsyncMock()):
         
        try:
            await main_module.redis_stream_consumer()
        except StopLoopException:
            pass
            
    assert main_module._live_state["metadata"]["telemetry_status"] == "DISCONNECTED"

