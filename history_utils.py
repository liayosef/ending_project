"""
history_utils.py
פונקציות לעיבוד והצגה של היסטוריית גלישה
"""

from collections import defaultdict
from datetime import datetime, timedelta


def is_obviously_technical(domain):
    """
    בודק אם הדומיין הוא טכני/פרסומי ולא מעניין להורים
    """
    if not domain or domain == 'לא ידוע':
        return True

    domain_lower = domain.lower()

    # דפוסים טכניים ברורים
    technical_patterns = [
        'analytics', 'tracking', 'ads', 'doubleclick', 'googletagmanager',
        'cdn', 'cache', 'static', 'assets', 'edge', 'akamai', 'cloudflare',
        'api', 'ws', 'websocket', 'ajax', 'xhr', 'heartbeat', 'status',
        'telemetry', 'metrics', 'logs', 'monitoring', 'beacon',
        'googlesyndication', 'googleadservices', 'facebook.com/tr',
        'connect.facebook.net', 'platform.twitter.com', 'fastly',
        'segments', 'pixel', 'clienttoken', 'spclient', 'apresolve',
        'insights', 'dealer', 'pdata', 'gateway', 'lh3.googleusercontent'
    ]

    for pattern in technical_patterns:
        if pattern in domain_lower:
            return True

    # תת-דומיינים ארוכים מדי (סימן לטכני)
    parts = domain_lower.split('.')
    if len(parts) > 4:  # יותר מדי תת-דומיינים
        return True

    # בדיקת דומיינים קצרים מדי או ארוכים מדי
    main_part = parts[0] if parts else ''
    if len(main_part) < 2 or len(main_part) > 20:
        return True

    # דומיינים שהם רק מספרים, קודים או תווים מוזרים
    if any(pattern in main_part for pattern in ['-v4', 'v4-', 'pdata', 'uuid']):
        return True

    # דומיינים עם מזהים ארוכים (כמו GUIDs)
    if len(main_part) > 15 and ('-' in main_part or any(c.isdigit() for c in main_part)):
        return True

    # דומיינים שהם רק קודי נמלים/שרתים או קיצורים טכניים
    technical_codes = [
        'lhr', 'cph', 'lfpg', 'bare', 'sbgr', 'hkg', 'gew1', 'k-aeu1',
        'lh3', 'ogs', 'vc', 'sb', 'exp', 'o22381'  # קודים טכניים נוספים
    ]
    if main_part in technical_codes:
        return True

    # דומיינים של אות בודדת או קצרים מדי (למעט TLD מוכרים)
    if len(main_part) <= 2 and main_part.lower() not in ['tv', 'me', 'be', 'go']:
        return True

    # בדיקת דומיינים עם תבניות טכניות
    if any(pattern in main_part for pattern in ['feedback-', 'signaler-', '-pa']):
        return True

    return False


def is_obviously_technical(domain):
    """
    בודק אם הדומיין הוא טכני/פרסומי ולא מעניין להורים
    """
    if not domain or domain == 'לא ידוע':
        return True

    domain_lower = domain.lower()

    # דפוסים טכניים ברורים
    technical_patterns = [
        'analytics', 'tracking', 'ads', 'doubleclick', 'googletagmanager',
        'cdn', 'cache', 'static', 'assets', 'edge', 'akamai', 'cloudflare',
        'api', 'ws', 'websocket', 'ajax', 'xhr', 'heartbeat', 'status',
        'telemetry', 'metrics', 'logs', 'monitoring', 'beacon',
        'googlesyndication', 'googleadservices', 'facebook.com/tr',
        'connect.facebook.net', 'platform.twitter.com', 'fastly',
        'segments', 'pixel', 'clienttoken', 'spclient', 'apresolve',
        'insights', 'dealer', 'pdata', 'gateway'
    ]

    for pattern in technical_patterns:
        if pattern in domain_lower:
            return True

    # תת-דומיינים ארוכים מדי (סימן לטכני)
    parts = domain_lower.split('.')
    if len(parts) > 4:  # יותר מדי תת-דומיינים
        return True

    # בדיקת דומיינים קצרים מדי או ארוכים מדי
    main_part = parts[0] if parts else ''
    if len(main_part) < 2 or len(main_part) > 20:
        return True

    # דומיינים שהם רק מספרים, קודים או תווים מוזרים
    if any(pattern in main_part for pattern in ['-v4', 'v4-', 'pdata', 'uuid']):
        return True

    # דומיינים עם מזהים ארוכים (כמו GUIDs)
    if len(main_part) > 15 and ('-' in main_part or any(c.isdigit() for c in main_part)):
        return True

    # דומיינים שהם רק קודי נמלים/שרתים
    airport_codes = ['lhr', 'cph', 'lfpg', 'bare', 'sbgr', 'hkg', 'gew1']
    if main_part in airport_codes:
        return True

    return False


def group_browsing_by_main_site(history_entries, time_window_minutes=30):
    """
    מקבץ פעילויות גלישה לפי אתר ראשי ובחלון זמן
    מסנן דומיינים טכניים לפני הקיבוץ
    """
    # סינון דומיינים טכניים לפני הקיבוץ
    filtered_entries = []
    for entry in history_entries:
        domain = entry.get('domain', '')
        if not is_obviously_technical(domain):
            filtered_entries.append(entry)

    print(f"[DEBUG] לפני סינון טכני: {len(history_entries)}, אחרי: {len(filtered_entries)}")

    grouped = defaultdict(list)

    for entry in filtered_entries:  # משתמש ברשימה המסוננת
        # נשתמש בשדה domain (הנתונים הישנים) או main_domain
        main_domain = entry.get('main_domain') or entry.get('domain', '')
        display_name = entry.get('display_name')

        # אם אין display_name, ננסה ליצור מהדומיין
        if not display_name and main_domain:
            clean_domain = main_domain.lower().replace('www.', '').replace('m.', '')
            site_name = clean_domain.split('.')[0]
            display_name = site_name.capitalize() if len(site_name) > 3 else site_name.upper()

        timestamp_str = entry.get('timestamp', '')

        # המרת זמן
        try:
            if 'T' in timestamp_str:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                continue
        except:
            continue

        # יצירת מפתח קיבוץ: אתר + חלון זמן
        time_slot = timestamp.replace(
            minute=(timestamp.minute // time_window_minutes) * time_window_minutes,
            second=0,
            microsecond=0
        )

        group_key = f"{display_name}_{time_slot.isoformat()}"
        grouped[group_key].append(entry)

    # המרה לרשימה מסודרת
    result = []
    for group_entries in grouped.values():
        if len(group_entries) == 1:
            # פעילות יחידה - נוסיף את השדות החסרים
            entry = group_entries[0]
            entry['original_domain'] = entry.get('domain', '')
            entry['main_domain'] = entry.get('main_domain', entry.get('domain', ''))
            if not entry.get('display_name'):
                # חילוץ שם תצוגה פשוט
                domain = entry.get('domain', '')
                if domain:
                    clean_domain = domain.lower().replace('www.', '').replace('m.', '')
                    site_name = clean_domain.split('.')[0]
                    entry['display_name'] = site_name.capitalize() if len(site_name) > 3 else site_name.upper()
            result.append(entry)
        else:
            # יצירת רשומה מקובצת
            first_entry = group_entries[0]
            last_entry = group_entries[-1]

            # מיון לפי זמן
            group_entries.sort(key=lambda x: x.get('timestamp', ''))

            # בדיקה אם יש גם חסימות וגם אישורים
            blocked_count = sum(1 for e in group_entries if e.get('was_blocked', False))
            allowed_count = len(group_entries) - blocked_count

            # יצירת תיאור הסטטוס
            if blocked_count > 0 and allowed_count > 0:
                status_description = f"{allowed_count} מותר, {blocked_count} חסום"
                was_blocked = True  # נסמן כחסום אם יש חסימות
            elif blocked_count > 0:
                status_description = f"{blocked_count} חסום"
                was_blocked = True
            else:
                status_description = f"{allowed_count} ביקורים"
                was_blocked = False

            # חילוץ display_name מהרשומה הראשונה
            display_name = first_entry.get('display_name')
            if not display_name:
                domain = first_entry.get('domain', '')
                if domain:
                    clean_domain = domain.lower().replace('www.', '').replace('m.', '')
                    site_name = clean_domain.split('.')[0]
                    display_name = site_name.capitalize() if len(site_name) > 3 else site_name.upper()

            # רשומה מקובצת
            grouped_entry = {
                'original_domain': first_entry.get('domain', ''),  # ✅ תיקון: משתמש בשדה domain
                'main_domain': first_entry.get('main_domain', first_entry.get('domain', '')),
                'display_name': display_name,
                'timestamp': first_entry.get('timestamp', ''),
                'was_blocked': was_blocked,
                'child_name': first_entry.get('child_name', ''),
                'is_grouped': True,
                'activity_count': len(group_entries),
                'status_description': status_description,
                'time_range': {
                    'start': group_entries[0].get('timestamp', ''),
                    'end': group_entries[-1].get('timestamp', '')
                }
            }
            result.append(grouped_entry)

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