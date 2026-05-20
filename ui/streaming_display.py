#!/usr/bin/env python3
"""
Streaming Display - Real-time UI updates as data arrives
Handles live rendering of phase data with progress tracking
"""

import streamlit as st
from typing import Dict, Any, Callable, Optional
import time
from datetime import datetime
from ui.dynamic_display import render_phase_data


class StreamingDisplay:
    """Manages real-time streaming display of phase data"""
    
    def __init__(self):
        """Initialize streaming display"""
        self.phase_containers = {}
        self.phase_data = {}
        self.phase_status = {
            1: 'pending',
            2: 'pending',
            3: 'pending',
            4: 'pending',
            5: 'pending'
        }
    
    def setup_phase_containers(self):
        """Setup containers for each phase"""
        st.markdown("---")
        st.subheader("📊 Analysis Results")
        
        # Create tabs for each phase
        tabs = st.tabs([
            "🏢 Phase 1: Business",
            "🌐 Phase 2: Infrastructure",
            "🖥️ Phase 3: Application",
            "🔗 Phase 4: Correlation",
            "📊 Phase 5: Risk"
        ])
        
        for phase_num, tab in enumerate(tabs, 1):
            with tab:
                # Create placeholder for phase data
                container = st.container()
                self.phase_containers[phase_num] = container
                
                # Show loading state initially
                with container:
                    col1, col2 = st.columns([3, 1])
                    with col1:
                        st.info(f"⏳ Phase {phase_num} analysis in progress...")
                    with col2:
                        status_placeholder = st.empty()
                        self.phase_status[phase_num] = 'pending'
    
    def update_phase_display(self, phase_num: int, data: Dict[str, Any], 
                            duration: float = 0, status: str = 'completed'):
        """Update display for a specific phase"""
        if phase_num not in self.phase_containers:
            return
        
        # Store data
        self.phase_data[phase_num] = data
        self.phase_status[phase_num] = status
        
        # Update container
        with self.phase_containers[phase_num]:
            # Clear previous content
            st.empty()
            
            # Show status
            if status == 'completed':
                st.success(f"✅ Phase {phase_num} completed in {duration:.2f}s")
            elif status == 'error':
                st.error(f"❌ Phase {phase_num} failed")
            else:
                st.info(f"⏳ Phase {phase_num} in progress...")
            
            st.divider()
            
            # Render phase data
            if data and 'error' not in data:
                render_phase_data(phase_num, data)
            elif 'error' in data:
                st.error(f"Error: {data.get('error', 'Unknown error')}")
    
    def show_progress_bar(self):
        """Show overall progress bar"""
        completed = sum(1 for status in self.phase_status.values() if status == 'completed')
        total = len(self.phase_status)
        progress = completed / total
        
        col1, col2 = st.columns([3, 1])
        with col1:
            st.progress(progress, text=f"Overall Progress: {int(progress * 100)}%")
        with col2:
            st.metric("Phases Complete", f"{completed}/{total}")
    
    def show_phase_summary(self):
        """Show summary of all phases"""
        st.markdown("---")
        st.subheader("📋 Analysis Summary")
        
        cols = st.columns(5)
        phase_names = [
            "Business",
            "Infrastructure",
            "Application",
            "Correlation",
            "Risk"
        ]
        
        for i, (phase_num, status) in enumerate(self.phase_status.items()):
            with cols[i]:
                status_icon = "✅" if status == 'completed' else "❌" if status == 'error' else "⏳"
                st.metric(f"Phase {phase_num}", f"{status_icon} {status.title()}")


class LiveStreamingDisplay:
    """Live streaming display with real-time updates"""
    
    def __init__(self):
        """Initialize live streaming display"""
        self.streaming_display = StreamingDisplay()
        self.callbacks = {}
    
    def setup(self):
        """Setup the streaming display"""
        self.streaming_display.setup_phase_containers()
    
    def register_phase_callback(self, phase_num: int, callback: Callable):
        """Register callback for phase completion"""
        if phase_num not in self.callbacks:
            self.callbacks[phase_num] = []
        self.callbacks[phase_num].append(callback)
    
    def on_phase_complete(self, phase_num: int, data: Dict[str, Any], duration: float = 0):
        """Handle phase completion"""
        # Update display
        self.streaming_display.update_phase_display(phase_num, data, duration, 'completed')
        
        # Trigger callbacks
        if phase_num in self.callbacks:
            for callback in self.callbacks[phase_num]:
                try:
                    callback(data)
                except Exception as e:
                    st.error(f"Callback error for Phase {phase_num}: {e}")
        
        # Update progress
        self.streaming_display.show_progress_bar()
    
    def on_phase_error(self, phase_num: int, error: str):
        """Handle phase error"""
        error_data = {'error': error}
        self.streaming_display.update_phase_display(phase_num, error_data, 0, 'error')
        self.streaming_display.show_progress_bar()
    
    def show_summary(self):
        """Show final summary"""
        self.streaming_display.show_phase_summary()
    
    def get_phase_data(self, phase_num: int) -> Optional[Dict[str, Any]]:
        """Get phase data"""
        return self.streaming_display.phase_data.get(phase_num)
    
    def get_all_data(self) -> Dict[int, Dict[str, Any]]:
        """Get all phase data"""
        return self.streaming_display.phase_data


class ProgressTracker:
    """Track and display analysis progress"""
    
    def __init__(self):
        """Initialize progress tracker"""
        self.progress_container = st.container()
        self.status_container = st.container()
        self.phases_status = {
            1: {'name': 'Business Domain', 'status': 'pending', 'progress': 0},
            2: {'name': 'Infrastructure', 'status': 'pending', 'progress': 0},
            3: {'name': 'Application', 'status': 'pending', 'progress': 0},
            4: {'name': 'Correlation', 'status': 'pending', 'progress': 0},
            5: {'name': 'Risk Assessment', 'status': 'pending', 'progress': 0}
        }
    
    def update_phase_status(self, phase_num: int, status: str, progress: int = 0):
        """Update phase status"""
        if phase_num in self.phases_status:
            self.phases_status[phase_num]['status'] = status
            self.phases_status[phase_num]['progress'] = progress
            self._render_progress()
    
    def _render_progress(self):
        """Render progress display"""
        with self.progress_container:
            st.markdown("### 📈 Analysis Progress")
            
            for phase_num, phase_info in self.phases_status.items():
                col1, col2, col3 = st.columns([2, 1, 1])
                
                with col1:
                    status_icon = {
                        'pending': '⚪',
                        'in_progress': '🟡',
                        'completed': '🟢',
                        'error': '🔴'
                    }.get(phase_info['status'], '❓')
                    
                    st.write(f"{status_icon} **{phase_info['name']}**")
                
                with col2:
                    st.progress(phase_info['progress'] / 100, text=f"{phase_info['progress']}%")
                
                with col3:
                    st.caption(phase_info['status'].upper())
    
    def get_overall_progress(self) -> int:
        """Get overall progress percentage"""
        total_progress = sum(p['progress'] for p in self.phases_status.values())
        return int(total_progress / len(self.phases_status))


def create_streaming_ui():
    """Create streaming UI for analysis"""
    live_display = LiveStreamingDisplay()
    live_display.setup()
    return live_display


def update_streaming_ui(live_display: LiveStreamingDisplay, phase_num: int, 
                       data: Dict[str, Any], duration: float = 0):
    """Update streaming UI with phase data"""
    if data and 'error' not in data:
        live_display.on_phase_complete(phase_num, data, duration)
    else:
        error_msg = data.get('error', 'Unknown error') if data else 'No data returned'
        live_display.on_phase_error(phase_num, error_msg)
