from flask import Flask, render_template, redirect, jsonify, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
import openai


app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
openai.api_key = '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'


# Import models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

class Purchase(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    place = db.Column(db.String(80), nullable=False)
    package = db.Column(db.String(80), nullable=False)
    date = db.Column(db.String(80), nullable=False)

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('signup.html')


@app.route('/signup', methods=['POST'])
def signup():
    username = request.form['username']
    password = request.form['password']
    if User.query.filter_by(username=username).first():
        flash('Username already exists!')
        return redirect(url_for('index'))
    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()
    session['user'] = username
    return redirect(url_for('home'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username, password=password).first()
    if user:
        session['user'] = username
        return redirect(url_for('home'))
    flash('Invalid credentials!')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))

@app.route('/home', methods=['GET'])
def home():
    if 'user' not in session:
        return redirect(url_for('index'))
    return render_template('home.html')

@app.route('/destination/<place>')
def destination(place):
    packages = {'premium': 2000, 'budget': 1000}
    return render_template('destination.html', place=place, packages=packages)

@app.route('/book', methods=['POST'])
def book():
    place = request.form['place']
    package = request.form['package']
    date = request.form['date']
    user = session['user']
    new_purchase = Purchase(username=user, place=place, package=package, date=date)
    db.session.add(new_purchase)
    db.session.commit()
    return redirect(url_for('purchases'))

@app.route('/purchases')
def purchases():
    user = session['user']
    purchases = Purchase.query.filter_by(username=user).all()
    return render_template('purchases.html', purchases=purchases)

@app.route('/edit/<int:purchase_id>', methods=['GET', 'POST'])
def edit_purchase(purchase_id):
    if 'user' not in session:
        return redirect(url_for('index'))
    purchase = Purchase.query.get_or_404(purchase_id)
    if request.method == 'POST':
        purchase.place = request.form['place']
        purchase.package = request.form['package']
        purchase.date = request.form['date']
        db.session.commit()
        flash('Booking updated successfully!')
        return redirect(url_for('purchases'))
    return render_template('edit.html', purchase=purchase)

@app.route('/delete/<int:purchase_id>', methods=['POST'])
def delete_purchase(purchase_id):
    if 'user' not in session:
        return redirect(url_for('index'))
    purchase = Purchase.query.get_or_404(purchase_id)
    db.session.delete(purchase)
    db.session.commit()
    flash('Booking deleted successfully!')
    return redirect(url_for('purchases'))

@app.route('/chat', methods=['POST'])
def chat():
    if request.method == 'POST':
        user_message = request.json.get('message')  # Fetch user's message from the request
        if not user_message:
            return {"error": "No message provided"}, 400

        # OpenAI API call (Updated for chat models)
        try:
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",  # or "gpt-4" for GPT-4 model
                messages=[
                    {"role": "user", "content": user_message}  # Send the user's message in the 'messages' array
                ]
            )
            ai_message = response['choices'][0]['message']['content']  # Extract AI's response
            return {"reply": ai_message}
        except Exception as e:
            return {"error": str(e)}, 500
    return jsonify({"error": "Invalid method"}), 405

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    app.run(debug=True)
