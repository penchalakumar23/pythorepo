#!/usr/bin/env python3
"""
Development startup script for SAML Flask app
"""
import os
import sys
from dotenv import load_dotenv

def setup_development():
    """Setup development environment"""
    # Load environment variables
    load_dotenv()
    
    # Set development flags
    os.environ['FLASK_ENV'] = 'development'
    os.environ['DEVELOPMENT'] = 'true'
    os.environ['FLASK_DEBUG'] = 'true'
    
    print("🔧 Setting up development environment...")
    print(f"📁 Current directory: {os.getcwd()}")
    
    # Check if SAML settings exist
    saml_dir = os.path.join(os.getcwd(), 'saml')
    settings_dev = os.path.join(saml_dir, 'settings_dev.json')
    
    if not os.path.exists(saml_dir):
        print("📁 Creating SAML directory...")
        os.makedirs(saml_dir, exist_ok=True)
    
    if not os.path.exists(settings_dev):
        print("⚠️  Warning: settings_dev.json not found in saml/ directory")
        print("   Please create it with your localhost configuration")
    
    print("✅ Development environment ready!")
    print("🌐 Starting Flask development server...")
    print("📱 Available endpoints:")
    print("   - http://localhost:5000 (Main app)")
    print("   - http://localhost:5000/dev/mock-sso (Mock login)")
    print("   - http://localhost:5000/dev/status (Dev status)")
    print("   - http://localhost:5000/metadata (SP metadata)")
    print()

if __name__ == '__main__':
    setup_development()
    
    # Import and run the Flask app
    try:
        from app import app  # Assuming your main file is app.py
        app.run(debug=True, host='0.0.0.0', port=5000)
    except ImportError:
        print("❌ Could not import app. Make sure your main Flask file is named 'app.py'")
        print("   Or modify the import statement in this script.")
        sys.exit(1)