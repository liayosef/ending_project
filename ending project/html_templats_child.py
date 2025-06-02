import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

REGISTRATION_HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
   <meta charset="UTF-8">
   <meta name="viewport" content="width=device-width, initial-scale=1.0">
   <title>Registration - Parental Control</title>
   <style>
       * {
           margin: 0;
           padding: 0;
           box-sizing: border-box;
       }

       html, body {
           height: 100%;
           width: 100%;
           font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
           background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
           display: flex;
           justify-content: center;
           align-items: center;
           overflow: hidden;
       }

       .full-container {
           position: fixed;
           top: 0;
           left: 0;
           right: 0;
           bottom: 0;
           display: flex;
           justify-content: center;
           align-items: center;
           background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
           min-height: 100vh;
           width: 100vw;
       }

       .form-container {
           background: rgba(255, 255, 255, 0.95);
           backdrop-filter: blur(10px);
           padding: 60px 50px;
           border-radius: 20px;
           width: 90%;
           max-width: 500px;
           box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
           text-align: center;
           border: 1px solid rgba(255, 255, 255, 0.2);
       }

       .logo-circle {
           background: linear-gradient(135deg, #4a6fa5, #6a5acd);
           width: 100px;
           height: 100px;
           border-radius: 50%;
           display: flex;
           align-items: center;
           justify-content: center;
           font-size: 50px;
           color: white;
           margin: 0 auto 30px;
           box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
       }

       h1 {
           color: #2c3e50;
           font-size: 32px;
           margin: 0 0 20px;
           font-weight: bold;
       }

       .subtitle {
           color: #555;
           font-size: 18px;
           margin-bottom: 40px;
           line-height: 1.5;
       }

       .form-group {
           margin-bottom: 30px;
           text-align: left;
       }

       label {
           display: block;
           font-weight: bold;
           margin-bottom: 10px;
           color: #2c3e50;
           font-size: 18px;
       }

       input[type="text"] {
           width: 100%;
           padding: 18px 20px;
           border: 2px solid #e1e8ed;
           border-radius: 12px;
           font-size: 18px;
           text-align: left;
           transition: all 0.3s ease;
           background: rgba(255, 255, 255, 0.9);
       }

       input[type="text"]:focus {
           outline: none;
           border-color: #4a6fa5;
           box-shadow: 0 0 0 3px rgba(74, 111, 165, 0.1);
           background: white;
       }

       .submit-btn {
           background: linear-gradient(135deg, #4a6fa5, #6a5acd);
           color: white;
           padding: 18px 40px;
           border: none;
           border-radius: 12px;
           font-size: 18px;
           font-weight: bold;
           cursor: pointer;
           width: 100%;
           margin-top: 20px;
           transition: all 0.3s ease;
           box-shadow: 0 5px 15px rgba(74, 111, 165, 0.3);
       }

       .submit-btn:hover {
           transform: translateY(-2px);
           box-shadow: 0 8px 25px rgba(74, 111, 165, 0.4);
       }

       .info-text {
           background: rgba(248, 249, 250, 0.9);
           padding: 20px;
           border-radius: 12px;
           border-left: 4px solid #4a6fa5;
           margin-top: 30px;
           font-size: 16px;
           color: #555;
           line-height: 1.5;
       }

       .message {
           padding: 15px;
           border-radius: 8px;
           margin-bottom: 20px;
           text-align: center;
       }

       .error-message {
           background-color: #f8d7da;
           color: #721c24;
           border: 1px solid #f5c6cb;
       }

       .success-message {
           background-color: #d4edda;
           color: #155724;
           border: 1px solid #c3e6cb;
       }

       .warning-message {
           background-color: #fff3cd;
           color: #856404;
           border: 1px solid #ffeaa7;
       }

       /* Animations */
       @keyframes fadeIn {
           from {
               opacity: 0;
               transform: translateY(30px);
           }
           to {
               opacity: 1;
               transform: translateY(0);
           }
       }

       .form-container {
           animation: fadeIn 0.8s ease-out;
       }

       /* Responsive */
       @media (max-width: 600px) {
           .form-container {
               padding: 40px 30px;
               margin: 20px;
               width: calc(100% - 40px);
           }

           h1 {
               font-size: 28px;
           }

           .logo-circle {
               width: 80px;
               height: 80px;
               font-size: 40px;
           }
       }
   </style>
</head>
<body>
   <div class="full-container">
       <div class="form-container">
           <div class="logo-circle">🛡️</div>
           <h1>Parental Control System</h1>
           <div class="subtitle">Internet access is restricted until system registration</div>
           <form method="post" action="/register">
               <div class="form-group">
                   <label for="child_name">👶 Your Name:</label>
                   <input type="text" id="child_name" name="child_name" placeholder="Enter your name..." required>
               </div>
               <button type="submit" class="submit-btn">🔐 Enter System</button>
           </form>

           <div class="info-text">
               💡 If your name is not registered in the system, ask your parents to add you through the control panel
           </div>
       </div>
   </div>
</body>
</html>'''

BLOCK_HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
   <meta charset="UTF-8">
   <title>Site Blocked - {child_name}</title>
   <style>
       body {{ 
           font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
           background: linear-gradient(135deg, #ff4757, #ff6b6b);
           min-height: 100vh;
           display: flex;
           justify-content: center;
           align-items: center;
           padding: 20px;
           margin: 0;
           color: white;
       }}
       .child-name-tag {{
           position: fixed;
           top: 20px;
           left: 20px;
           background: rgba(0,0,0,0.8);
           padding: 10px 20px;
           border-radius: 25px;
           font-size: 14px;
           font-weight: bold;
       }}
       .block-container {{
           background: rgba(255,255,255,0.1);
           backdrop-filter: blur(10px);
           padding: 50px;
           border-radius: 20px;
           max-width: 600px;
           width: 100%;
           box-shadow: 0 15px 35px rgba(0,0,0,0.3);
           border: 1px solid rgba(255,255,255,0.2);
           text-align: center;
       }}
       .block-icon {{
           background: rgba(255,255,255,0.2);
           width: 100px;
           height: 100px;
           border-radius: 50%;
           display: flex;
           align-items: center;
           justify-content: center;
           font-size: 50px;
           margin: 0 auto 30px;
       }}
       h1 {{
           font-size: 36px;
           margin: 0 0 20px;
           font-weight: bold;
       }}
       .warning-box {{
           background: rgba(255,255,255,0.15);
           border: 2px solid rgba(255,255,255,0.3);
           border-radius: 15px;
           padding: 25px;
           margin: 30px 0;
       }}
       .warning-box p {{
           margin: 10px 0;
           font-size: 18px;
       }}
       .warning-box strong {{
           font-weight: bold;
           color: #fff;
       }}
       .description {{
           font-size: 18px;
           line-height: 1.6;
           margin: 20px 0;
           opacity: 0.9;
       }}
       .advice {{
           background: rgba(255,255,255,0.1);
           padding: 20px;
           border-radius: 10px;
           margin-top: 30px;
           font-size: 16px;
       }}
   </style>
</head>
<body>
   <div class="child-name-tag">{child_name}</div>
   <div class="block-container">
       <div class="block-icon">🚫</div>
       <h1>Site Blocked!</h1>

       <div class="warning-box">
           <p><strong>Site:</strong> {host}</p>
           <p><strong>Time:</strong> {current_time}</p>
           <p><strong>Child:</strong> {child_name}</p>
       </div>

       <div class="description">
           Access to this site has been blocked by the parental control system
       </div>

       <div class="advice">
           💡 If you think this is a mistake or you need access to this site for studying, contact your parents
       </div>
   </div>
</body>
</html>'''


def create_error_page(title, message, back_button=True, retry_button=False):
    """
    Create error page - fixed version that always returns valid content.

    Args:
        title (str): Error page title
        message (str): Error message content
        back_button (bool): Whether to show back button
        retry_button (bool): Whether to show retry button

    Returns:
        str: Complete HTML error page
    """
    # Ensure parameters are valid
    if not title:
        title = "Error"
    if not message:
        message = "A system error occurred"

    buttons = ""

    if retry_button:
        buttons += '''
       <button onclick="tryAgain()" class="submit-btn retry-btn">Try Again</button>
       '''

    if back_button:
        buttons += '''
       <button onclick="goBack()" class="submit-btn back-btn">Go Back</button>
       '''

    script = '''
   <script>
       function goBack() {
           console.log("Attempting to go back...");

           try {
               if (window.history.length > 1) {
                   window.history.back();
                   setTimeout(function() {
                       window.location.href = '/';
                   }, 1000);
               } else {
                   window.location.href = '/';
               }
           } catch (e) {
               console.log("Error going back:", e);
               window.location.href = '/';
           }
       }

       function tryAgain() {
           console.log("Returning to registration page...");
           window.location.href = '/';
       }

       window.onload = function() {
           console.log("History length:", window.history.length);

           var backButton = document.querySelector('button[onclick*="goBack"]');
           if (backButton && window.history.length <= 1) {
               backButton.textContent = 'Registration Page';
           }
       }

       window.addEventListener('error', function(e) {
           console.log('JavaScript error:', e.error);
       });
   </script>
   '''

    html_content = f'''<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
   <meta charset="UTF-8">
   <title>{title}</title>
   <style>
       body {{ 
           font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
           background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
           min-height: 100vh;
           display: flex;
           justify-content: center;
           align-items: center;
           padding: 20px;
           margin: 0;
       }}
       .container {{
           background: white;
           padding: 50px;
           border-radius: 15px;
           max-width: 500px;
           width: 100%;
           box-shadow: 0 10px 20px rgba(0,0,0,0.1);
           text-align: center;
       }}
       .icon {{ 
           font-size: 60px; 
           margin-bottom: 20px; 
       }}
       h1 {{ 
           color: #e74c3c; 
           font-size: 24px; 
           margin-bottom: 20px; 
       }}
       p {{ 
           color: #666; 
           font-size: 16px; 
           line-height: 1.6; 
       }}
       .submit-btn {{
           background: #4a6fa5;
           color: white;
           padding: 12px 30px;
           border: none;
           border-radius: 8px;
           font-size: 16px;
           font-weight: bold;
           cursor: pointer;
           margin: 10px 5px;
           display: inline-block;
           transition: all 0.3s ease;
       }}
       .submit-btn:hover {{
           opacity: 0.9;
           transform: translateY(-2px);
       }}
       .button-container {{
           margin-top: 30px;
       }}
       .retry-btn {{
           background: #28a745;
           margin-right: 10px;
       }}
       .back-btn {{
           background: #95a5a6;
       }}
   </style>
</head>
<body>
   <div class="container">
       <div class="icon">❌</div>
       <h1>{title}</h1>
       <p>{message}</p>
       <div class="button-container">
           {buttons}
       </div>
   </div>
   {script}
</body>
</html>'''

    return html_content


def create_success_page(title, message):
    """
    Create success page - fixed version.

    Args:
        title (str): Success page title
        message (str): Success message content

    Returns:
        str: Complete HTML success page
    """
    if not title:
        title = "Success"
    if not message:
        message = "Operation completed successfully"

    html_content = f'''<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
   <meta charset="UTF-8">
   <title>{title}</title>
   <style>
       body {{ 
           font-family: 'Segoe UI', Tahoma, Arial, sans-serif;
           background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
           min-height: 100vh;
           display: flex;
           justify-content: center;
           align-items: center;
           padding: 20px;
           margin: 0;
       }}
       .container {{
           background: white;
           padding: 50px;
           border-radius: 15px;
           max-width: 500px;
           width: 100%;
           box-shadow: 0 10px 20px rgba(0,0,0,0.1);
           text-align: center;
       }}
       .icon {{ 
           font-size: 60px; 
           margin-bottom: 20px; 
       }}
       h1 {{ 
           color: #28a745; 
           font-size: 24px; 
           margin-bottom: 20px; 
       }}
       p {{ 
           color: #666; 
           font-size: 16px; 
           line-height: 1.6; 
       }}
       .highlight {{ 
           background: #d4edda; 
           padding: 15px; 
           border-radius: 8px; 
           margin: 20px 0; 
           border-left: 4px solid #28a745; 
       }}
       .auto-close {{
           color: #888;
           font-size: 14px;
           margin-top: 20px;
       }}
   </style>
</head>
<body>
   <div class="container">
       <div class="icon">🎉</div>
       <h1>{title}</h1>
       <div class="highlight">{message}</div>
       <p>You can close this page and start browsing the internet</p>
       <div class="auto-close">This page will close automatically in <span id="countdown">5</span> seconds</div>
   </div>

   <script>
       let countdown = 5;
       const countdownElement = document.getElementById('countdown');

       const timer = setInterval(function() {{
           countdown--;
           countdownElement.textContent = countdown;

           if (countdown <= 0) {{
               clearInterval(timer);
               window.close();
               setTimeout(function() {{
                   window.location.href = '/';
               }}, 500);
           }}
       }}, 1000);
   </script>
</body>
</html>'''

    return html_content


def create_connection_error_page():
    """
    Special error page for parent server connection issues.

    Returns:
        str: HTML error page for connection problems
    """
    return create_error_page(
        "Parent Server Unavailable",
        "Cannot connect to the parental control server.<br><br>"
        " Make sure that:<br>"
        "• Parent server is running<br>"
        "• Network connection is working<br>"
        "• Firewall settings allow connection<br><br>"
        " Try starting the parent server and then refresh the page",
        back_button=True,
        retry_button=True
    )


def create_not_registered_page(child_name):
    """
    Special error page for unregistered child.

    Args:
        child_name (str): Name of the child attempting to register

    Returns:
        str: HTML error page for unregistered child
    """
    return create_error_page(
        "Not Registered in System",
        f"The name '{child_name}' is not registered in the parental control system.<br><br>"
        " Ask your parents to add you through the control panel:<br>"
        "1. Manage Children<br>"
        "2. Add New Child<br>"
        "3. Enter your name<br><br>"
        "After your parents add you, come back and try again",
        back_button=True,
        retry_button=True
    )