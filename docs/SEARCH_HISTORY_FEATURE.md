# Search History Feature

## Overview

The Search History feature enables users to track and manage all domain analyses performed in the BSI application. It provides a structured way to retrieve previously analyzed domains and view their analysis status.

## Features

### 1. Automatic Search History Tracking
- Every domain analysis is automatically added to the search history
- Tracks first search time, last search time, and search count
- Maintains analysis status (pending, in_progress, completed, failed)
- Stores completion percentage for ongoing analyses

### 2. Recent Searches Sidebar
Located in the main app sidebar, displays:
- Last 5 recently searched domains
- Status indicator (✅ completed, ⏳ in progress, ⭕ pending)
- Quick access buttons to load previous analyses
- Search bar to find specific domains

### 3. Search History Page
Dedicated page accessible from the Streamlit multi-page navigation:

#### Recent Searches Tab
- Shows last 20 searched domains
- Displays domain, status, search count, and timestamp
- One-click access to load previous analyses
- Delete functionality to remove search history

#### Search Tab
- Search bar to find domains by name
- Fuzzy matching on domain names
- Shows all matching results
- Quick access to load analyses

#### Statistics Tab
- Total unique domains searched
- Total number of searches
- Completed analyses count
- Database statistics (cache hits, active cache entries)

## Database Schema

### search_history Table
```sql
CREATE TABLE search_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    analysis_id INTEGER,
    first_searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_searched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    search_count INTEGER DEFAULT 1,
    status TEXT DEFAULT 'pending',
    completion_percentage INTEGER DEFAULT 0,
    FOREIGN KEY (analysis_id) REFERENCES analysis_history(id)
)
```

### Indexes
- `idx_search_history_domain`: Fast domain lookups
- `idx_search_history_last_searched`: Sorted by recency

## API Methods

### Database Manager Methods

#### `add_to_search_history(domain, analysis_id, status, completion_percentage)`
Adds or updates a domain in search history.

```python
db.add_to_search_history(
    domain="example.com",
    analysis_id=1,
    status="completed",
    completion_percentage=100
)
```

#### `get_search_history(limit=20)`
Retrieves recent searches ordered by last searched time.

```python
recent = db.get_search_history(limit=10)
# Returns list of dicts with domain, status, search_count, etc.
```

#### `search_history(search_term)`
Searches for domains matching a search term.

```python
results = db.search_history("example")
# Returns all domains containing "example"
```

#### `get_search_history_stats()`
Returns search history statistics.

```python
stats = db.get_search_history_stats()
# Returns: {
#     'total_unique_domains': int,
#     'total_searches': int,
#     'completed_analyses': int
# }
```

## Integration with Main App

### Sidebar Integration
The main app sidebar now includes:
1. Search bar for quick domain lookup
2. Recent searches list (last 5)
3. Status indicators for each domain
4. One-click access to load analyses

### Analysis Flow
1. User enters domain and clicks "Start Analysis"
2. Database creates analysis record
3. Search history is updated with `in_progress` status
4. During analysis, completion percentage is tracked
5. Upon completion, status is updated to `completed`
6. Results are stored and linked to search history

### Session State Handling
- `selected_domain`: Used to pass domain selection from search history to main input
- `navigate_to_domain`: Used for multi-page navigation

## Usage Examples

### Example 1: View Recent Searches
```python
from core.database import get_db_manager

db = get_db_manager()
recent = db.get_search_history(limit=5)

for record in recent:
    print(f"{record['domain']}: {record['status']} ({record['search_count']}x)")
```

### Example 2: Search for a Domain
```python
results = db.search_history("amazon")
for result in results:
    print(f"Found: {result['domain']}")
```

### Example 3: Get Statistics
```python
stats = db.get_search_history_stats()
print(f"Total unique domains: {stats['total_unique_domains']}")
print(f"Completed analyses: {stats['completed_analyses']}")
```

## File Structure

```
Sakthi-BSI/
├── core/
│   └── database.py              # Enhanced with search_history methods
├── ui/
│   └── search_history.py        # SearchHistoryUI component
├── pages/
│   ├── 0_Analyze.py            # Main analysis page
│   └── 1_Search_History.py     # Search history page
├── app.py                       # Updated with search history integration
└── docs/
    └── SEARCH_HISTORY_FEATURE.md  # This file
```

## Data Retrieval Structure

### Search History Record Structure
```python
{
    'id': int,                          # Unique ID
    'domain': str,                      # Domain name
    'analysis_id': int,                 # Link to analysis_history
    'first_searched_at': str,           # ISO timestamp
    'last_searched_at': str,            # ISO timestamp
    'search_count': int,                # Number of times searched
    'status': str,                      # pending/in_progress/completed/failed
    'completion_percentage': int        # 0-100
}
```

### Analysis History Record Structure
```python
{
    'id': int,                          # Unique ID
    'domain': str,                      # Domain name
    'created_at': str,                  # ISO timestamp
    'updated_at': str,                  # ISO timestamp
    'status': str,                      # pending/in_progress/completed/failed
    'completion_percentage': int,       # 0-100
    'total_duration_seconds': float,    # Total analysis time
    'notes': str                        # Optional notes
}
```

## Performance Considerations

### Indexes
- Domain lookups are O(1) with unique index
- Recent searches are O(log n) with timestamp index
- Search operations are O(n) but fast with LIKE queries

### Caching
- Search results are not cached (always fresh)
- Database queries are optimized with indexes
- Thread-safe operations with locks

## Future Enhancements

1. **Export Search History**: Export as CSV/JSON
2. **Search Filters**: Filter by status, date range, completion percentage
3. **Bulk Operations**: Delete multiple searches, bulk status updates
4. **Search Analytics**: Charts showing search trends over time
5. **Favorites**: Mark frequently used domains as favorites
6. **Tags**: Add custom tags to searches for organization
7. **Comparison**: Compare analyses of the same domain over time
8. **Notifications**: Alert when analysis completes
