#!/usr/bin/env python3
"""
Callback Handler - Connects data streaming to UI updates
Manages real-time callbacks from phases to display components
"""

import streamlit as st
from typing import Dict, Any, Callable, Optional
import logging

logger = logging.getLogger(__name__)


class UICallbackHandler:
    """Handles callbacks from data streamer to UI"""
    
    def __init__(self):
        """Initialize callback handler"""
        self.phase_callbacks = {}
        self.ui_update_queue = []
        self.display_containers = {}
    
    def register_display_container(self, phase_num: int, container):
        """Register a display container for a phase"""
        self.display_containers[phase_num] = container
        logger.info(f"Registered display container for Phase {phase_num}")
    
    def create_phase_callback(self, phase_num: int):
        """Create a callback function for a phase"""
        def callback(data: Dict[str, Any]):
            """Callback function that updates UI"""
            try:
                # Queue UI update
                self.ui_update_queue.append({
                    'phase': phase_num,
                    'data': data,
                    'timestamp': __import__('datetime').datetime.now()
                })
                
                # Update display if container exists
                if phase_num in self.display_containers:
                    self._update_container(phase_num, data)
                
                logger.info(f"✅ Phase {phase_num} callback executed")
            except Exception as e:
                logger.error(f"❌ Error in Phase {phase_num} callback: {e}")
        
        return callback
    
    def _update_container(self, phase_num: int, data: Dict[str, Any]):
        """Update display container with phase data"""
        container = self.display_containers[phase_num]
        
        with container:
            # Clear previous content
            st.empty()
            
            # Show success message
            st.success(f"✅ Phase {phase_num} data received")
            
            # Display data
            if data and 'error' not in data:
                st.json(data)
            else:
                st.error(f"Error: {data.get('error', 'Unknown error')}")
    
    def get_queued_updates(self) -> list:
        """Get all queued UI updates"""
        updates = self.ui_update_queue.copy()
        self.ui_update_queue.clear()
        return updates
    
    def process_updates(self):
        """Process all queued updates"""
        updates = self.get_queued_updates()
        for update in updates:
            phase = update['phase']
            data = update['data']
            self._update_container(phase, data)


class StreamingCallbackManager:
    """Manages streaming callbacks for real-time display"""
    
    def __init__(self):
        """Initialize callback manager"""
        self.callbacks = {}
        self.phase_data = {}
        self.phase_status = {}
    
    def register_callback(self, phase_num: int, callback: Callable):
        """Register a callback for a phase"""
        if phase_num not in self.callbacks:
            self.callbacks[phase_num] = []
        self.callbacks[phase_num].append(callback)
        logger.info(f"Registered callback for Phase {phase_num}")
    
    def trigger_callback(self, phase_num: int, data: Dict[str, Any], 
                        duration: float = 0, status: str = 'completed'):
        """Trigger callbacks for a phase"""
        # Store data and status
        self.phase_data[phase_num] = data
        self.phase_status[phase_num] = status
        
        # Trigger all callbacks
        if phase_num in self.callbacks:
            for callback in self.callbacks[phase_num]:
                try:
                    callback(data, duration, status)
                    logger.info(f"✅ Callback triggered for Phase {phase_num}")
                except Exception as e:
                    logger.error(f"❌ Callback error for Phase {phase_num}: {e}")
    
    def get_phase_data(self, phase_num: int) -> Optional[Dict[str, Any]]:
        """Get phase data"""
        return self.phase_data.get(phase_num)
    
    def get_phase_status(self, phase_num: int) -> Optional[str]:
        """Get phase status"""
        return self.phase_status.get(phase_num)
    
    def get_all_data(self) -> Dict[int, Dict[str, Any]]:
        """Get all phase data"""
        return self.phase_data.copy()
    
    def get_all_status(self) -> Dict[int, str]:
        """Get all phase status"""
        return self.phase_status.copy()


class RealtimeDisplayUpdater:
    """Updates display in real-time as data arrives"""
    
    def __init__(self):
        """Initialize real-time updater"""
        self.phase_placeholders = {}
        self.phase_data = {}
    
    def create_phase_placeholder(self, phase_num: int):
        """Create a placeholder for phase data"""
        placeholder = st.empty()
        self.phase_placeholders[phase_num] = placeholder
        return placeholder
    
    def update_phase_display(self, phase_num: int, data: Dict[str, Any], 
                            duration: float = 0):
        """Update phase display with new data"""
        if phase_num not in self.phase_placeholders:
            return
        
        self.phase_data[phase_num] = data
        
        with self.phase_placeholders[phase_num].container():
            # Show completion status
            col1, col2 = st.columns([3, 1])
            with col1:
                st.success(f"✅ Phase {phase_num} completed in {duration:.2f}s")
            with col2:
                st.metric("Duration", f"{duration:.2f}s")
            
            st.divider()
            
            # Display data
            if data and 'error' not in data:
                # Import dynamic display
                from ui.dynamic_display import render_phase_data
                render_phase_data(phase_num, data)
            else:
                st.error(f"Error: {data.get('error', 'Unknown error')}")
    
    def get_phase_data(self, phase_num: int) -> Optional[Dict[str, Any]]:
        """Get phase data"""
        return self.phase_data.get(phase_num)
    
    def get_all_data(self) -> Dict[int, Dict[str, Any]]:
        """Get all phase data"""
        return self.phase_data.copy()


def create_ui_callback_handler() -> UICallbackHandler:
    """Create UI callback handler"""
    return UICallbackHandler()


def create_streaming_callback_manager() -> StreamingCallbackManager:
    """Create streaming callback manager"""
    return StreamingCallbackManager()


def create_realtime_updater() -> RealtimeDisplayUpdater:
    """Create real-time display updater"""
    return RealtimeDisplayUpdater()
