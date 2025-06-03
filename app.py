from flask import Flask, request, redirect, session, url_for, render_template_string
#from onelogin.saml2.auth import OneLogin_Saml2_Auth
#from onelogin.saml2.settings import OneLogin_Saml2_Settings
#from onelogin.saml2.utils import OneLogin_Saml2_Utils
import os
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here-change-in-production')

# Development flag
DEVELOPMENT = os.getenv('FLASK_ENV') == 'development' or os.getenv('DEVELOPMENT', 'True').lower() == 'true'

def init_saml_auth(req):
    # auth = OneLogin_Saml2_Auth(req, custom_base_path=get_saml_settings_path())
    # return auth
    return none
    
def prepare_flask_request(request):
    url_data = request.url.split('?')
    
    # For development, handle HTTP requests properly
    scheme = 'https' if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https' else 'http'
    
    return {
        'https': 'on' if scheme == 'https' else 'off',
        'http_host': request.headers.get('HTTP_X_FORWARDED_HOST', request.host),
        'server_port': request.environ.get('SERVER_PORT', '5000'),
        'script_name': request.path,
        'get_data': request.args.copy(),
        'post_data': request.form.copy(),
        'query_string': url_data[1] if len(url_data) > 1 else ''
    }

def get_saml_settings_path():
    return os.path.join(os.path.dirname(__file__), 'saml')

# HTML Templates as strings for simplicity
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>SAML Test Login</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 50px auto; padding: 20px; }
        .container { border: 1px solid #ddd; padding: 30px; border-radius: 8px; background: #f9f9f9; }
        .btn { background: #007cba; color: white; padding: 12px 24px; border: none; border-radius: 4px; 
               text-decoration: none; display: inline-block; margin: 5px; cursor: pointer; }
        .btn:hover { background: #005a87; }
        .btn-mock { background: #28a745; }
        .btn-mock:hover { background: #218838; }
        .dev-notice { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; 
                     margin-bottom: 20px; color: #856404; }
        .info { background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 4px; 
               margin-bottom: 20px; color: #0c5460; }
        .separator { margin: 20px 0; color: #666; text-align: center; }
        small a { color: #666; text-decoration: none; }
        small a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 SAML SSO Login Test</h2>
                
        {% if development %}
        <div class="dev-notice">
            <strong>🚧 Development Mode</strong><br>
            Mock login available for offline testing
        </div>
        {% endif %}
        
        <p><strong>Test with IdM:</strong></p>
        <a href="{{ url_for('login') }}" class="btn">🚀 Login</a>
        
        {% if development %}
        <div class="separator">- OR -</div>
        <a href="{{ url_for('mock_sso') }}" class="btn btn-mock">🧪 Mock Login (Dev Only)</a>
        {% endif %}
        
        <div style="margin-top: 30px;">
            <small>
                <a href="{{ url_for('metadata') }}">📄 SP Metadata</a>
                {% if development %}
                | <a href="{{ url_for('dev_status') }}">📊 Dev Status</a>
                | <a href="{{ url_for('saml_info') }}">ℹ️ SAML Info</a>
                {% endif %}
            </small>
        </div>
        
        <div style="margin-top: 20px; font-size: 12px; color: #666;">
            <strong>SAML-test.id Test Users:</strong><br>
            Username: <code>user1@example.com</code>, Password: <code>user1pass</code><br>
            Username: <code>user2@example.com</code>, Password: <code>user2pass</code>
        </div>
    </div>
</body>
</html>
'''

DASHBOARD_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Dashboard - Authenticated</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: Arial, sans-serif; max-width: 1000px; margin: 20px auto; padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; 
                 border-bottom: 2px solid #007cba; padding-bottom: 20px; margin-bottom: 30px; }
        .user-info { background: #e8f4fd; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .attributes { background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .session-info { background: #fff3cd; padding: 20px; border-radius: 8px; }
        .btn { background: #dc3545; color: white; padding: 10px 20px; border: none; 
               border-radius: 4px; text-decoration: none; display: inline-block; }
        .btn:hover { background: #c82333; }
        .attribute-item { margin-bottom: 8px; padding: 10px; background: white; border-radius: 4px; }
        .attribute-key { font-weight: bold; color: #007cba; }
        .attribute-value { color: #666; margin-left: 10px; }
        .success { color: #28a745; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>✅ SAML Authentication Successful!</h1>
        <a href="{{ url_for('logout') }}" class="btn">🚪 Logout</a>
    </div>
    
    <div class="user-info">
        <h3>👤 Welcome, {{ session.get('samlNameId', 'User') }}!</h3>
        <p class="success">You have successfully authenticated via SAML SSO with SAML-test.id</p>
    </div>

    {% if attributes %}
    <div class="attributes">
        <h3>📋 User Attributes from IdP</h3>
        <table>
            <thead>
                <tr><th>Attribute</th><th>Value(s)</th></tr>
            </thead>
            <tbody>
                {% for key, values in attributes.items() %}
                <tr>
                    <td class="attribute-key">{{ key }}</td>
                    <td class="attribute-value">
                        {% if values is iterable and values is not string %}
                            {% for value in values %}
                                {{ value }}{% if not loop.last %}, {% endif %}
                            {% endfor %}
                        {% else %}
                            {{ values }}
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </div>
    {% endif %}

    <div class="session-info">
        <h3>🔒 Session Information</h3>
        <table>
            <tr><td><strong>Name ID:</strong></td><td>{{ session.get('samlNameId', 'Not available') }}</td></tr>
            <tr><td><strong>Name ID Format:</strong></td><td>{{ session.get('samlNameIdFormat', 'Not available') }}</td></tr>
            <tr><td><strong>Session Index:</strong></td><td>{{ session.get('samlSessionIndex', 'Not available') }}</td></tr>
            <tr><td><strong>Authentication Time:</strong></td><td>{{ moment().format('YYYY-MM-DD HH:mm:ss') if moment else 'Just now' }}</td></tr>
        </table>
    </div>

    <div style="margin-top: 30px; text-align: center;">
        <small style="color: #666;">
            Powered by SAML-test.id • 
            <a href="https://samltest.id/" target="_blank" style="color: #666;">Learn more</a>
        </small>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    if 'samlUserdata' in session:
        return render_template_string(DASHBOARD_TEMPLATE, 
                                    attributes=session.get('samlAttributes', {}))
    else:
        return render_template_string(LOGIN_TEMPLATE, development=DEVELOPMENT)

@app.route('/login')
def login():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.login())

@app.route('/sso', methods=['POST'])
def sso():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    auth.process_response()

    errors = auth.get_errors()

    if not errors:
        session['samlUserdata'] = auth.get_attributes()
        session['samlNameId'] = auth.get_nameid()
        session['samlNameIdFormat'] = auth.get_nameid_format()
        session['samlSessionIndex'] = auth.get_session_index()
        
        if auth.get_attributes():
            session['samlAttributes'] = auth.get_attributes()
        
        self_url = OneLogin_Saml2_Utils.get_self_url(req)
        return redirect(url_for('index'))
        # if 'RelayState' in request.form and self_url != request.form['RelayState']:
        #     return redirect(auth.redirect_to(request.form['RelayState']))
        # else:
        #     return redirect(url_for('index'))
    else:
        print("SAML Errors: ", auth.get_last_error_reason())
        return f"<h2>❌ Authentication Failed</h2><p>Error: {auth.get_last_error_reason()}</p><a href='{url_for('index')}'>Try Again</a>", 400

@app.route('/sls', methods=['GET', 'POST'])
def sls():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    url = auth.process_slo(delete_session_cb=lambda: session.clear())
    errors = auth.get_errors()
    
    if not errors:
        if url is not None:
            return redirect(url)
        else:
            return redirect(url_for('index'))
    else:
        print("SLO Errors: ", auth.get_last_error_reason())
        return f"<h2>❌ Logout Failed</h2><p>Error: {auth.get_last_error_reason()}</p>", 400

@app.route('/logout')
def logout():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    return redirect(auth.logout())
    # session.clear()
    # return redirect(url_for('index'))

@app.route('/metadata')
def metadata():
    settings = OneLogin_Saml2_Settings(custom_base_path=get_saml_settings_path())
    metadata = settings.get_sp_metadata()
    errors = settings.check_sp_settings()

    if errors:
        print("Metadata Errors: ", errors)
        return f"<h2>❌ Metadata Generation Failed</h2><p>Errors: {errors}</p>", 500

    resp = app.response_class(
        response=metadata,
        status=200,
        mimetype='text/xml',
    )
    return resp

# Development-only routes
@app.route('/dev/mock-sso', methods=['GET', 'POST'])
def mock_sso():
    if not DEVELOPMENT:
        return "Not available in production", 404
    
    session['samlUserdata'] = {
        'email': ['mockuser@example.com'],
        'first_name': ['Mock'],
        'last_name': ['User'],
        'role': ['Developer']
    }
    session['samlNameId'] = 'mockuser@example.com'
    session['samlNameIdFormat'] = 'urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress'
    session['samlSessionIndex'] = 'mock_session_' + str(hash('mock'))
    session['samlAttributes'] = session['samlUserdata']
    
    return redirect(url_for('index'))

@app.route('/dev/status')
def dev_status():
    if not DEVELOPMENT:
        return "Not available in production", 404
    
    return {
        'development_mode': DEVELOPMENT,
        'session_active': 'samlUserdata' in session,
        'user_id': session.get('samlNameId', 'Not logged in'),
        'endpoints': {
            'mock_login': url_for('mock_sso'),
            'real_login': url_for('login'),
            'metadata': url_for('metadata'),
            'saml_info': url_for('saml_info')
        },
        'session_data': dict(session) if 'samlUserdata' in session else {}
    }

@app.route('/saml/info')
def saml_info():
    if not DEVELOPMENT:
        return "Not available in production", 404
    
    info_html = '''
    <h2>🔧 SAML Configuration Info</h2>
    <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 20px auto; padding: 20px;">
        <h3>📡 Identity Provider: SAML-test.id</h3>
        <ul>
            <li><strong>Entity ID:</strong> https://samltest.id/saml/idp</li>
            <li><strong>SSO URL:</strong> https://samltest.id/idp/profile/SAML2/Redirect/SSO</li>
            <li><strong>SLO URL:</strong> https://samltest.id/idp/profile/SAML2/Redirect/SLO</li>
        </ul>
        
        <h3>🏠 Service Provider (Your App)</h3>
        <ul>
            <li><strong>Entity ID:</strong> http://localhost:5000/metadata</li>
            <li><strong>ACS URL:</strong> http://localhost:5000/sso</li>
            <li><strong>SLS URL:</strong> http://localhost:5000/sls</li>
        </ul>
        
        <h3>👥 Test Users</h3>
        <table border="1" style="border-collapse: collapse; width: 100%;">
            <tr><th>Username</th><th>Password</th><th>Email</th></tr>
            <tr><td>user1@example.com</td><td>user1pass</td><td>user1@example.com</td></tr>
            <tr><td>user2@example.com</td><td>user2pass</td><td>user2@example.com</td></tr>
        </table>
        
        <div style="margin-top: 20px;">
            <a href="/" style="background: #007cba; color: white; padding: 10px 20px; text-decoration: none; border-radius: 4px;">← Back to App</a>
        </div>
    </div>
    '''
    return info_html

if __name__ == '__main__':
    if DEVELOPMENT:
        print("🚀 Starting SAML Test App with SAML-test.id")
        print("🌐 App URL: http://localhost:5000")
        print("🔗 SAML-test.id: https://samltest.id/")
        print("📋 Test Users: user1@example.com/user1pass, user2@example.com/user2pass")
        print()
    
    app.run(debug=DEVELOPMENT, host='0.0.0.0', port=5000)