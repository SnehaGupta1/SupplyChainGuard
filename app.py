"""
SupplyChainGuard - Main Application Entry
"""

from api.routes import create_app

app = create_app()

if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("  SupplyChainGuard v1.0")
    print("  Real-Time Supply Chain Malware Detection")
    print("=" * 50)
    print("\n  API running at: http://localhost:5000")
    print("  Dashboard at:   http://localhost:5000")
    print("  API Docs at:    http://localhost:5000/api/health")
    print("=" * 50 + "\n")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )