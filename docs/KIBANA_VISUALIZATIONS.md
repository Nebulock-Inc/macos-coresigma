# Kibana Visualizations Guide

This guide explains how to create visualizations for the macOS Security Telemetry Dashboard.

## Quick Start

### Option 1: Use Saved Searches (Recommended)

The dashboard is automatically created with saved searches. Access it at:
- http://localhost:5601/app/dashboards

### Option 2: Create Visualizations Manually

Follow these steps to create visualizations in Kibana 8.x:

## Creating Visualizations

### 1. Event Collection Timeline (Line Graph)

1. Go to **Visualize Library** → **Create visualization**
2. Select **Lens** (recommended for Kibana 8.x)
3. Choose data view: **macos-telemetry-esf-***
4. Configure:
   - **X-axis**: `@timestamp` (Date Histogram)
   - **Y-axis**: Count
   - **Chart type**: Line
5. Save as: "macOS Event Collection Timeline"

### 2. Event Types Distribution (Pie Chart)

1. Create new visualization → **Lens**
2. Data view: **macos-telemetry-esf-***
3. Configure:
   - **Primary metric**: Count
   - **Breakdown by**: `event_name.keyword` (Terms)
   - **Chart type**: Pie
4. Save as: "macOS Event Types Distribution"

### 3. Event Types Data Table

1. Create new visualization → **Lens**
2. Data view: **macos-telemetry-esf-***
3. Configure:
   - **Primary metric**: Count
   - **Breakdown by**: `event_name.keyword` (Terms)
   - **Chart type**: Table
   - Add secondary breakdown: `event_type` (Terms)
4. Save as: "macOS Event Types Data Table"

### 4. Top Processes (Horizontal Bar Chart)

1. Create new visualization → **Lens**
2. Data view: **macos-telemetry-esf-***
3. Configure:
   - **X-axis**: `Image.keyword` (Terms, Top 10)
   - **Y-axis**: Count
   - **Chart type**: Horizontal Bar
4. Save as: "macOS Top Processes"

## Creating the Dashboard

1. Go to **Dashboards** → **Create dashboard**
2. Click **Add** → **Add panels**
3. Add the visualizations you created
4. Add saved searches as panels
5. Arrange and resize panels
6. Save as: "macOS Security Telemetry Dashboard"

## Alternative: Using Discover View

For quick monitoring without creating visualizations:

1. Go to **Discover**
2. Select data view: **macos-telemetry-esf-***
3. Use saved searches from the sidebar
4. View events in real-time

## Field Reference

Useful fields for visualizations:

- `@timestamp` - Event time (for timelines)
- `event_name` - Event type name (exec, fork, create, etc.)
- `event_type` - Numeric event type
- `Image` - Process executable path
- `User` - Username
- `ProcessId` - Process ID
- `CommandLine` - Command line arguments

