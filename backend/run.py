from app import create_app, db
from app.models import User, Analysis

app = create_app()

@app.shell_context_processor
def make_shell_context():
    #make database models available in flask shell
    return {'db': db, 'User': User, 'Analysis': Analysis}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)