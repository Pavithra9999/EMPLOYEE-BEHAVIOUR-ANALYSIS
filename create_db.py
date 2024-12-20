from app import db, User

with app.app_context():
    db.create_all()
    # Optionally, add an initial user to test
    # initial_user = User(first_name='Initial', last_name='User', email='initial@example.com', username='initial', password=generate_password_hash('password', method='pbkdf2:sha256'))
    # db.session.add(initial_user)
    # db.session.commit()
