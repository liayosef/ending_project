import logging
from collections import defaultdict
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def is_obviously_technical(domain):
    """
    Check if domain is technical and not interesting to parents.

    Analyzes domain patterns to identify technical, tracking, advertising,
    and other automated traffic that should be filtered from browsing history.

    Args:
        domain (str): Domain name to analyze

    Returns:
        bool: True if domain appears to be technical/automated, False otherwise
    """
    if not domain or domain == 'unknown':
        return True

    domain_lower = domain.lower()

    # Specific technical domains - expanded list
    technical_patterns = [
        'analytics', 'tracking', 'doubleclick', 'googletagmanager',
        'cdn.', 'cache.', 'static.', 'assets.', 'edge.', 'akamai', 'cloudflare',
        'api.', 'ws.', 'websocket', 'ajax', 'xhr', 'heartbeat', 'status.',
        'telemetry', 'metrics', 'logs.', 'monitoring', 'beacon',
        'googlesyndication', 'googleadservices', 'facebook.com/tr',
        'connect.facebook.net', 'platform.twitter.com',
        'pixel.', 'clienttoken', 'spclient', 'apresolve',
        'dealer', 'pdata', 'lh3.googleusercontent',
        # Additional technical domains that appeared in usage:
        'fastly-insights.com', 'contentsquare.net', 'casalemedia.com',
        'demdex.net', 'scorecardresearch.com', 'sentry.io',
        'googleoptimize.com', 'clarity.ms', 'optimizely.com',
        'mktoresp.com', 'googlezip.net', 'heyday', 'jquery.com'
    ]

    for pattern in technical_patterns:
        if pattern in domain_lower:
            return True

    # Domains for complete removal (Google + Microsoft background traffic)
    unwanted_domains = [
        'google.com', 'google.co.il', 'google.net', 'googleapis.com',
        'microsoft.com', 'live.com', 'outlook.com', 'office.com'
    ]

    for unwanted in unwanted_domains:
        if unwanted in domain_lower:
            return True

    # Additional existing checks...
    parts = domain_lower.split('.')
    if len(parts) > 5:
        return True

    main_part = parts[0] if parts else ''
    if len(main_part) < 2 or len(main_part) > 25:
        return True

    return False


def group_browsing_by_main_site(history_entries, time_window_minutes=30):
    """
    Group browsing history by main site with time window deduplication.

    Groups browsing history entries by site and time to reduce noise and
    provide a cleaner view of actual browsing activity.

    Args:
        history_entries (list): List of browsing history entries
        time_window_minutes (int): Time window in minutes for grouping

    Returns:
        list: Filtered and grouped history entries
    """
    sorted_entries = sorted(history_entries,
                            key=lambda x: x.get('timestamp', ''),
                            reverse=True)
    seen_sites = set()
    result = []

    for entry in sorted_entries:
        display_name = entry.get('display_name', 'unknown')
        timestamp = entry.get('timestamp', '')

        # Create unique key: name + time (in minutes)
        try:
            if 'T' in timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_key = dt.strftime('%H:%M')  # hour:minute
                site_key = f"{display_name}_{time_key}"
            else:
                site_key = display_name
        except:
            site_key = display_name

        # Add only if we haven't seen this site in this minute
        if site_key not in seen_sites:
            seen_sites.add(site_key)
            result.append(entry)

    return result


def format_simple_grouped_entry(entry):
    """
    Format grouped entry simply - backward compatible with old data.

    Formats browsing history entries for display with proper fallbacks
    for missing fields and consistent styling across different data formats.

    Args:
        entry (dict): Browsing history entry to format

    Returns:
        str: HTML formatted entry for display
    """
    # Try all possibilities to find the domain
    original_domain = (entry.get('original_domain') or
                       entry.get('domain') or
                       entry.get('main_domain') or
                       'unknown')

    main_domain = entry.get('main_domain', original_domain)
    display_name = entry.get('display_name')

    # If no display_name, try to create one from domain
    if not display_name or display_name == 'unknown':
        if original_domain and original_domain != 'unknown':
            # Simple function to extract site name
            clean_domain = original_domain.lower().replace('www.', '').replace('m.', '')
            domain_parts = clean_domain.split('.')
            if len(domain_parts) >= 2:
                site_name = domain_parts[0]
                # Improve display
                if len(site_name) <= 3:
                    display_name = site_name.upper()  # Short sites
                else:
                    display_name = site_name.capitalize()  # Long sites
            else:
                display_name = original_domain
        else:
            display_name = "Unknown Site"

    timestamp = entry.get('timestamp', 'unknown')
    was_blocked = entry.get('was_blocked', False)
    child_name = entry.get('child_name', 'unknown')

    is_grouped = entry.get('is_grouped', False)
    status_description = entry.get('status_description', '')

    # Format date
    try:
        if 'T' in timestamp:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            formatted_time = dt.strftime('%d/%m/%Y %H:%M')
        else:
            formatted_time = timestamp
    except:
        formatted_time = timestamp

    # Format time range if it's a group
    if is_grouped and 'time_range' in entry:
        try:
            start_time = datetime.fromisoformat(entry['time_range']['start'].replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(entry['time_range']['end'].replace('Z', '+00:00'))

            # If same day - show only hour range
            if start_time.date() == end_time.date():
                time_display = f"{start_time.strftime('%H:%M')}-{end_time.strftime('%H:%M')}"
            else:
                time_display = formatted_time
        except:
            time_display = formatted_time
    else:
        time_display = formatted_time.split()[1] if ' ' in formatted_time else formatted_time

    status_class = 'status-blocked' if was_blocked else 'status-allowed'

    # Status description - simple
    if is_grouped and status_description and 'blocked' in status_description.lower():
        status_text = 'Blocked'  # If there are blocks in group - show "Blocked"
    else:
        status_text = 'Blocked' if was_blocked else 'Allowed'

    # Build simple HTML
    domain_html = f'<span title="{original_domain}" class="site-name">{display_name}</span>'

    # Add main domain if different (but without visit count)
    if main_domain != original_domain and main_domain:
        domain_html += f'<br><small class="main-domain">({main_domain})</small>'

    return f'''
       <div class="history-item {'grouped-item' if is_grouped else ''}">
           <div class="domain-info">
               <div class="domain-name">{domain_html}</div>
               <div class="domain-time">{time_display} • {child_name}</div>
           </div>
           <div class="status-badge {status_class}">{status_text}</div>
       </div>
   '''


# Additional CSS for grouping (already defined in template, but here for reference)
GROUPING_CSS = """
.grouped-item {
   background: #f8f9fa;
   border-left: 4px solid #4a6fa5;
}

.activity-badge {
   background: #17a2b8;
   color: white;
   padding: 2px 6px;
   border-radius: 10px;
   font-size: 11px;
   font-weight: bold;
}

.grouped-item .status-badge {
   min-width: 120px;
   font-size: 11px;
}

.site-name {
   font-weight: bold;
   font-size: 16px;
   color: #333;
}

.main-domain {
   color: #666;
   font-style: italic;
   font-size: 12px;
}

.domain-name {
   line-height: 1.4;
}

.history-item:hover .site-name {
   color: #4a6fa5;
}
"""