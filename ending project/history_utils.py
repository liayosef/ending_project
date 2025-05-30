from collections import defaultdict
from datetime import datetime, timedelta


def is_obviously_technical(domain):
    """בודק אם הדומיין הוא טכני ולא מעניין להורים"""
    if not domain or domain == 'לא ידוע':
        return True

    domain_lower = domain.lower()

    # דומיינים טכניים ספציפיים - הרחבה של הרשימה
    technical_patterns = [
        'analytics', 'tracking', 'doubleclick', 'googletagmanager',
        'cdn.', 'cache.', 'static.', 'assets.', 'edge.', 'akamai', 'cloudflare',
        'api.', 'ws.', 'websocket', 'ajax', 'xhr', 'heartbeat', 'status.',
        'telemetry', 'metrics', 'logs.', 'monitoring', 'beacon',
        'googlesyndication', 'googleadservices', 'facebook.com/tr',
        'connect.facebook.net', 'platform.twitter.com',
        'pixel.', 'clienttoken', 'spclient', 'apresolve',
        'dealer', 'pdata', 'lh3.googleusercontent',
        # דומיינים טכניים נוספים שהופיעו אצלך:
        'fastly-insights.com', 'contentsquare.net', 'casalemedia.com',
        'demdex.net', 'scorecardresearch.com', 'sentry.io',
        'googleoptimize.com', 'clarity.ms', 'optimizely.com',
        'mktoresp.com', 'googlezip.net', 'heyday', 'jquery.com'
    ]

    for pattern in technical_patterns:
        if pattern in domain_lower:
            return True

    # דומיינים להסרה מוחלטת (Google + Microsoft ברקע)
    unwanted_domains = [
        'google.com', 'google.co.il', 'google.net', 'googleapis.com',
        'microsoft.com', 'live.com', 'outlook.com', 'office.com'
    ]

    for unwanted in unwanted_domains:
        if unwanted in domain_lower:
            return True

    # שאר הבדיקות הקיימות...
    parts = domain_lower.split('.')
    if len(parts) > 5:
        return True

    main_part = parts[0] if parts else ''
    if len(main_part) < 2 or len(main_part) > 25:
        return True

    return False

def group_browsing_by_main_site(history_entries, time_window_minutes=30):
    sorted_entries = sorted(history_entries,
                            key=lambda x: x.get('timestamp', ''),
                            reverse=True)
    seen_sites = set()
    result = []

    for entry in sorted_entries:
        display_name = entry.get('display_name', 'לא ידוע')
        timestamp = entry.get('timestamp', '')

        # יצירת מפתח ייחודי: שם + זמן (בדקות)
        try:
            if 'T' in timestamp:
                from datetime import datetime
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                time_key = dt.strftime('%H:%M')  # שעה:דקה
                site_key = f"{display_name}_{time_key}"
            else:
                site_key = display_name
        except:
            site_key = display_name

        # הוסף רק אם לא ראינו את האתר באותה דקה
        if site_key not in seen_sites:
            seen_sites.add(site_key)
            result.append(entry)

    return result


def format_simple_grouped_entry(entry):
    """עיצוב רשומה מקובצת פשוטה - תואם לאחור עם נתונים ישנים"""

    # נסה כל האפשרויות למצוא את הדומיין
    original_domain = (entry.get('original_domain') or
                       entry.get('domain') or
                       entry.get('main_domain') or
                       'לא ידוע')

    main_domain = entry.get('main_domain', original_domain)
    display_name = entry.get('display_name')

    # אם אין display_name, ננסה ליצור אחד מהדומיין
    if not display_name or display_name == 'לא ידוע':
        if original_domain and original_domain != 'לא ידוע':
            # פונקציה פשוטה לחילוץ שם אתר
            clean_domain = original_domain.lower().replace('www.', '').replace('m.', '')
            domain_parts = clean_domain.split('.')
            if len(domain_parts) >= 2:
                site_name = domain_parts[0]
                # שיפור התצוגה
                if len(site_name) <= 3:
                    display_name = site_name.upper()  # אתרים קצרים
                else:
                    display_name = site_name.capitalize()  # אתרים ארוכים
            else:
                display_name = original_domain
        else:
            display_name = "אתר לא ידוע"

    timestamp = entry.get('timestamp', 'לא ידוע')
    was_blocked = entry.get('was_blocked', False)
    child_name = entry.get('child_name', 'לא ידוע')

    is_grouped = entry.get('is_grouped', False)
    status_description = entry.get('status_description', '')

    # עיצוב התאריך
    try:
        if 'T' in timestamp:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            formatted_time = dt.strftime('%d/%m/%Y %H:%M')
        else:
            formatted_time = timestamp
    except:
        formatted_time = timestamp

    # עיצוב טווח זמנים אם זה קיבוץ
    if is_grouped and 'time_range' in entry:
        try:
            start_time = datetime.fromisoformat(entry['time_range']['start'].replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(entry['time_range']['end'].replace('Z', '+00:00'))

            # אם זה באותו היום - נציג רק טווח שעות
            if start_time.date() == end_time.date():
                time_display = f"{start_time.strftime('%H:%M')}-{end_time.strftime('%H:%M')}"
            else:
                time_display = formatted_time
        except:
            time_display = formatted_time
    else:
        time_display = formatted_time.split()[1] if ' ' in formatted_time else formatted_time

    status_class = 'status-blocked' if was_blocked else 'status-allowed'

    # תיאור הסטטוס - פשוט
    if is_grouped and status_description and 'חסום' in status_description:
        status_text = 'חסום'  # אם יש חסימות בקיבוץ - נראה "חסום"
    else:
        status_text = 'חסום' if was_blocked else 'מותר'

    # בניית HTML פשוט
    domain_html = f'<span title="{original_domain}" class="site-name">{display_name}</span>'

    # הוספת הדומיין הראשי אם שונה (אבל ללא מספר ביקורים)
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


# CSS נוסף לקיבוץ (כבר מוגדר בתבנית, אבל כאן לעיון)
grouping_css = """
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