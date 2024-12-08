from app import app
from app import app, chat
from app import app, db, Purchase
from app import app, db, User
from app import app, destination
from app import app, openai
from flask import Flask
from flask import Flask, json
from flask import Flask, jsonify
from flask import Flask, render_template
from flask import Flask, session
from flask import Flask, session, url_for
from flask import Flask, url_for
from flask import Flask, url_for, session
from flask import session
from flask import session, url_for
from flask import url_for
from flask import url_for, session
from flask_sqlalchemy import SQLAlchemy
from unittest.mock import patch
import json
import pytest

class TestApp:

    @pytest.fixture
    def client(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        client = app.test_client()
        with app.app_context():
            db.create_all()
        yield client
        with app.app_context():
            db.drop_all()

    @pytest.fixture
    def client_2(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        with app.test_client() as client_2:
            with app.app_context():
                db.create_all()
            yield client_2
            with app.app_context():
                db.drop_all()

    @pytest.fixture
    def client_3(self):
        app.config['TESTING'] = True
        with app.test_client() as client_3:
            yield client_3

    @pytest.fixture
    def client_4(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        with app.test_client() as client_4:
            with app.app_context():
                db.create_all()
            yield client_4

    @pytest.fixture(autouse=True)
    def setup_db(self):
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['TESTING'] = True
        with app.app_context():
            db.create_all()
            yield
            db.session.remove()
            db.drop_all()

    def test_book_database_error(self, client_4, mocker):
        """Test booking when database error occurs"""
        with client_4.session_transaction() as sess:
            sess['user'] = 'testuser'
        
        mocker.patch.object(db.session, 'commit', side_effect=Exception('Database error'))
        
        response = client_4.post('/book', data={
            'place': 'TestPlace',
            'package': 'TestPackage',
            'date': '2023-07-01'
        })
        assert response.status_code == 500
        assert b"An error occurred while booking" in response.data

    def test_book_empty_input(self, client_4):
        """Test booking with empty input"""
        with client_4.session_transaction() as sess:
            sess['user'] = 'testuser'
        
        response = client_4.post('/book', data={})
        assert response.status_code == 400
        assert b"Missing required fields" in response.data

    def test_book_invalid_date(self, client_4):
        """Test booking with invalid date format"""
        with client_4.session_transaction() as sess:
            sess['user'] = 'testuser'
        
        response = client_4.post('/book', data={
            'place': 'TestPlace',
            'package': 'TestPackage',
            'date': 'invalid-date'
        })
        assert response.status_code == 400
        assert b"Invalid date format" in response.data

    def test_book_invalid_package(self, client_4):
        """Test booking with invalid package"""
        with client_4.session_transaction() as sess:
            sess['user'] = 'testuser'
        
        response = client_4.post('/book', data={
            'place': 'TestPlace',
            'package': 'InvalidPackage',
            'date': '2023-07-01'
        })
        assert response.status_code == 400
        assert b"Invalid package selected" in response.data

    def test_book_successful_purchase(self):
        """
        Test that a new purchase is successfully added to the database
        and the user is redirected to the purchases page.
        """
        with app.test_client() as client:
            with app.app_context():
                # Set up test data
                client.post('/login', data={'username': 'testuser', 'password': 'testpass'})
                
                # Make a POST request to book a trip
                response = client.post('/book', data={
                    'place': 'Test Place',
                    'package': 'Test Package',
                    'date': '2023-07-01'
                })

                # Check if the response is a redirect
                assert response.status_code == 302
                assert response.location == url_for('purchases')

                # Verify that the purchase was added to the database
                purchase = Purchase.query.filter_by(username='testuser').first()
                assert purchase is not None
                assert purchase.place == 'Test Place'
                assert purchase.package == 'Test Package'
                assert purchase.date == '2023-07-01'

                # Clean up the test data
                db.session.delete(purchase)
                db.session.commit()

    def test_book_unauthenticated(self, client_4):
        """Test booking without user authentication"""
        response = client_4.post('/book', data={
            'place': 'TestPlace',
            'package': 'TestPackage',
            'date': '2023-07-01'
        })
        assert response.status_code == 302
        assert response.headers['Location'] == '/'

    def test_chat_2(self):
        """
        Test chat function when a valid message is provided.
        """
        with app.test_client() as client:
            with patch('openai.ChatCompletion.create') as mock_create:
                # Mock the OpenAI API response
                mock_create.return_value = {
                    'choices': [{'message': {'content': 'Mocked AI response'}}]
                }

                # Send a POST request with a valid message
                response = client.post('/chat', 
                                       data=json.dumps({'message': 'Hello, AI!'}),
                                       content_type='application/json')

                # Check if the response status code is 200 (OK)
                assert response.status_code == 200

                # Check if the response contains the expected reply
                data = json.loads(response.data)
                assert 'reply' in data
                assert data['reply'] == 'Mocked AI response'

                # Verify that the OpenAI API was called with the correct parameters
                mock_create.assert_called_once_with(
                    model="gpt-3.5-turbo",
                    messages=[{"role": "user", "content": "Hello, AI!"}]
                )

    def test_chat_3(self):
        """
        Test chat() function when the request method is not POST.
        Expects a 405 status code with an "Invalid method" error message.
        """
        with app.test_client() as client:
            response = client.get('/chat')
            assert response.status_code == 405
            assert response.get_json() == {"error": "Invalid method"}

    def test_chat_api_exception(self, client_3, monkeypatch):
        """
        Test chat function when OpenAI API raises an exception
        """
        def mock_create(*args, **kwargs):
            raise Exception("API Error")

        monkeypatch.setattr(openai.ChatCompletion, "create", mock_create)
        response = client_3.post('/chat', json={"message": "Hello"})
        assert response.status_code == 500
        assert "error" in json.loads(response.data)

    def test_chat_empty_input(self, client_3):
        """
        Test chat function with empty input
        """
        response = client_3.post('/chat', json={})
        assert response.status_code == 400
        assert json.loads(response.data) == {"error": "No message provided"}

    def test_chat_incorrect_format(self, client_3):
        """
        Test chat function with incorrect format (sending form data instead of JSON)
        """
        response = client_3.post('/chat', data={"message": "Hello"})
        assert response.status_code == 400
        assert json.loads(response.data) == {"error": "No message provided"}

    def test_chat_invalid_input(self, client_3):
        """
        Test chat function with invalid input (non-string message)
        """
        response = client_3.post('/chat', json={"message": 123})
        assert response.status_code == 400
        assert json.loads(response.data) == {"error": "No message provided"}

    def test_chat_invalid_method(self):
        """
        Test chat() function when the request method is not POST.
        Expects a 405 status code with an "Invalid method" error message.
        """
        with app.test_client() as client:
            response = client.get('/chat')
            assert response.status_code == 405
            assert response.get_json() == {"error": "Invalid method"}

    def test_chat_invalid_method_2(self):
        """
        Test chat endpoint with an invalid HTTP method (GET).
        Expects a 405 status code with an error message.
        """
        client = app.test_client()
        response = client.get('/chat')
        
        assert response.status_code == 405
        assert json.loads(response.data) == {"error": "Invalid method"}

    def test_chat_long_input(self, client_3):
        """
        Test chat function with extremely long input
        """
        long_message = "a" * 10000  # Assuming 10000 characters is beyond the accepted limit
        response = client_3.post('/chat', json={"message": long_message})
        assert response.status_code == 400
        assert "error" in json.loads(response.data)

    def test_chat_missing_message_key(self, client_3):
        """
        Test chat function with missing 'message' key in JSON payload
        """
        response = client_3.post('/chat', json={"wrong_key": "Hello"})
        assert response.status_code == 400
        assert json.loads(response.data) == {"error": "No message provided"}

    def test_chat_no_message_provided(self):
        """
        Test chat endpoint when no message is provided in the request.
        Expects a 400 status code with an error message.
        """
        client = app.test_client()
        response = client.post('/chat', json={})
        
        assert response.status_code == 400
        assert json.loads(response.data) == {"error": "No message provided"}

    def test_chat_openai_exception(self, mocker):
        """
        Test chat endpoint when OpenAI API raises an exception.
        Expects a 500 status code with an error message.
        """
        mocker.patch.object(openai.ChatCompletion, 'create', side_effect=Exception("API Error"))
        
        client = app.test_client()
        response = client.post('/chat', json={"message": "Hello"})
        
        assert response.status_code == 500
        assert json.loads(response.data) == {"error": "API Error"}

    @pytest.mark.parametrize("user_message", ["Hello", "How are you?"])
    def test_chat_successful_response(self, user_message, mocker):
        """
        Test chat endpoint with a valid message.
        Expects a 200 status code with a reply from the AI.
        """
        mock_response = {
            'choices': [{'message': {'content': 'AI response'}}]
        }
        mocker.patch.object(openai.ChatCompletion, 'create', return_value=mock_response)
        
        client = app.test_client()
        response = client.post('/chat', json={"message": user_message})
        
        assert response.status_code == 200
        assert json.loads(response.data) == {"reply": "AI response"}

    def test_chat_wrong_http_method(self, client_3):
        """
        Test chat function with wrong HTTP method (GET instead of POST)
        """
        response = client_3.get('/chat')
        assert response.status_code == 405
        assert json.loads(response.data) == {"error": "Invalid method"}

    def test_delete_purchase_database_error(self, client_2, monkeypatch):
        """
        Test delete_purchase when a database error occurs
        """
        with client_2.session_transaction() as sess:
            sess['user'] = 'testuser'
        
        # Create a test purchase
        purchase = Purchase(username='testuser', place='TestPlace', package='TestPackage', date='2023-01-01')
        with app.app_context():
            db.session.add(purchase)
            db.session.commit()
            purchase_id = purchase.id

        # Mock db.session.commit to raise an exception
        def mock_commit():
            raise Exception("Database error")

        monkeypatch.setattr(db.session, 'commit', mock_commit)

        response = client_2.post(f'/delete/{purchase_id}')
        assert response.status_code == 500

    def test_delete_purchase_invalid_id_type(self, client_2):
        """
        Test delete_purchase with an invalid ID type (string instead of int)
        """
        with client_2.session_transaction() as sess:
            sess['user'] = 'testuser'
        
        response = client_2.post('/delete/invalid')
        assert response.status_code == 404

    def test_delete_purchase_method_not_allowed(self, client_2):
        """
        Test delete_purchase with GET method instead of POST
        """
        with client_2.session_transaction() as sess:
            sess['user'] = 'testuser'
        
        response = client_2.get('/delete/1')
        assert response.status_code == 405

    def test_delete_purchase_nonexistent_id(self, client_2):
        """
        Test delete_purchase with a non-existent purchase ID
        """
        with client_2.session_transaction() as sess:
            sess['user'] = 'testuser'
        
        response = client_2.post('/delete/9999')
        assert response.status_code == 404

    def test_delete_purchase_unauthenticated(self, client_2):
        """
        Test delete_purchase when user is not authenticated
        """
        response = client_2.post('/delete/1')
        assert response.status_code == 302
        assert response.headers['Location'] == '/'

    def test_delete_purchase_when_user_not_in_session(self):
        """
        Test delete_purchase when 'user' is not in session.
        Expected behavior: redirects to index page.
        """
        with app.test_client() as client:
            # Ensure 'user' is not in session
            with client.session_transaction() as sess:
                if 'user' in sess:
                    del sess['user']

            # Create a test purchase
            purchase = Purchase(username='testuser', place='testplace', package='testpackage', date='2023-01-01')
            db.session.add(purchase)
            db.session.commit()

            # Attempt to delete the purchase
            response = client.post(f'/delete/{purchase.id}')

            # Check if it redirects to index
            assert response.status_code == 302
            assert response.location == url_for('index', _external=True)

            # Verify the purchase was not deleted
            assert Purchase.query.get(purchase.id) is not None

        # Clean up
        db.session.delete(purchase)
        db.session.commit()

    def test_destination_packages_content(self):
        """
        Test that the destination function returns the correct packages.
        """
        with app.test_client() as client:
            response = client.get('/destination/TestPlace')
            assert response.status_code == 200
            assert b'premium' in response.data
            assert b'budget' in response.data
            assert b'2000' in response.data
            assert b'1000' in response.data

    def test_destination_renders_template_with_correct_data(self):
        """
        Test that the destination function renders the correct template with the expected data.
        """
        with app.test_request_context():
            # Arrange
            place = "Paris"
            expected_packages = {'premium': 2000, 'budget': 1000}

            # Act
            with app.test_client() as client:
                response = client.get(f'/destination/{place}')

            # Assert
            assert response.status_code == 200
            
            # Check if render_template was called with correct arguments
            with pytest.raises(RuntimeError) as excinfo:
                render_template('destination.html', place=place, packages=expected_packages)
            assert "destination.html" in str(excinfo.value)
            assert f"place={place}" in str(excinfo.value)
            assert f"packages={expected_packages}" in str(excinfo.value)

    def test_destination_with_empty_place(self):
        """
        Test the destination function with an empty place parameter.
        """
        with app.test_client() as client:
            response = client.get('/destination/')
            assert response.status_code == 404

    def test_destination_with_invalid_place(self):
        """
        Test the destination function with an invalid place parameter.
        """
        with app.test_client() as client:
            response = client.get('/destination/<script>alert("XSS")</script>')
            assert response.status_code == 200
            assert b'<script>alert("XSS")</script>' in response.data

    def test_destination_with_long_place_name(self):
        """
        Test the destination function with a very long place name.
        """
        long_place_name = 'a' * 1000
        with app.test_client() as client:
            response = client.get(f'/destination/{long_place_name}')
            assert response.status_code == 200
            assert long_place_name.encode() in response.data

    def test_destination_with_special_characters(self):
        """
        Test the destination function with special characters in the place name.
        """
        special_place = '!@#$%^&*()'
        with app.test_client() as client:
            response = client.get(f'/destination/{special_place}')
            assert response.status_code == 200
            assert special_place.encode() in response.data

    def test_edit_purchase_redirect_when_user_not_in_session(self):
        """
        Test that edit_purchase redirects to index when user is not in session
        """
        with app.test_client() as client:
            # Clear the session to ensure 'user' is not present
            with client.session_transaction() as sess:
                sess.clear()

            # Create a test purchase
            test_purchase = Purchase(username='testuser', place='TestPlace', package='TestPackage', date='2023-01-01')
            db.session.add(test_purchase)
            db.session.commit()

            # Make a GET request to edit_purchase
            response = client.get(f'/edit/{test_purchase.id}')

            # Assert that we are redirected to the index page
            assert response.status_code == 302
            assert response.location == url_for('index', _external=True)

            # Clean up
            db.session.delete(test_purchase)
            db.session.commit()

    def test_home_2(self):
        """
        Test that the home route renders the home template when user is in session
        """
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = 'testuser'
            
            response = client.get('/home')
            
            assert response.status_code == 200
            assert b'home.html' in response.data

    def test_home_redirect(self):
        with app.test_client() as client:
            response = client.get('/home', follow_redirects=True)
            assert response.status_code == 200
            assert b'login.html' in response.data

    def test_home_redirects_when_user_not_in_session(self):
        """
        Test that the home route redirects to index when user is not in session.
        """
        with app.test_client() as client:
            with client.session_transaction() as sess:
                # Ensure 'user' is not in session
                if 'user' in sess:
                    del sess['user']
            
            response = client.get('/home')
            
            assert response.status_code == 302
            assert response.location == url_for('index', _external=True)

    def test_home_with_empty_user_session(self, client_3):
        """
        Test that accessing /home with an empty user session redirects to index.
        """
        with client_3.session_transaction() as sess:
            sess['user'] = ''
        response = client_3.get('/home')
        assert response.status_code == 302
        assert response.location == '/'

    def test_home_with_invalid_session(self, client_3):
        """
        Test that accessing /home with an invalid session key redirects to index.
        """
        with client_3.session_transaction() as sess:
            sess['invalid_key'] = 'some_value'
        response = client_3.get('/home')
        assert response.status_code == 302
        assert response.location == '/'

    def test_home_with_post_method(self, client_3):
        """
        Test that accessing /home with POST method is not allowed.
        """
        response = client_3.post('/home')
        assert response.status_code == 405

    def test_home_with_query_parameters(self, client_3):
        """
        Test that accessing /home with query parameters still works as expected.
        """
        with client_3.session_transaction() as sess:
            sess['user'] = 'test_user'
        response = client_3.get('/home?param=value')
        assert response.status_code == 200

    def test_home_with_valid_user_session(self, client_3):
        """
        Test that accessing /home with a valid user session returns the home page.
        """
        with client_3.session_transaction() as sess:
            sess['user'] = 'test_user'
        response = client_3.get('/home')
        assert response.status_code == 200

    def test_home_without_user_session(self, client_3):
        """
        Test that accessing /home without a user session redirects to index.
        """
        response = client_3.get('/home')
        assert response.status_code == 302
        assert response.location == '/'

    def test_index_returns_login_template(self):
        """
        Test that the index route returns the login.html template
        """
        client = app.test_client()
        response = client.get('/')
        
        assert response.status_code == 200
        assert b'login.html' in response.data

    def test_index_returns_login_template_2(self):
        """
        Test that the index route returns the login template.
        """
        client = app.test_client()
        response = client.get('/')
        assert response.status_code == 200
        assert b'login.html' in response.data

    def test_index_with_malformed_request(self):
        """
        Test the index route with a malformed request.
        """
        client = app.test_client()
        response = client.get('/', headers={'Content-Type': 'application/json'})
        assert response.status_code == 200  # Should still return 200 as it doesn't process the content type
        assert b'login.html' in response.data

    def test_index_with_non_existent_template(self):
        """
        Test the index route when the template doesn't exist.
        """
        with app.app_context():
            app.template_folder = 'non_existent_folder'
            client = app.test_client()
            with pytest.raises(Exception):
                client.get('/')

    def test_index_with_post_request(self):
        """
        Test that the index route does not accept POST requests.
        """
        client = app.test_client()
        response = client.post('/')
        assert response.status_code == 405

    def test_index_with_query_parameters(self):
        """
        Test that the index route ignores query parameters.
        """
        client = app.test_client()
        response = client.get('/?param=value')
        assert response.status_code == 200
        assert b'login.html' in response.data

    def test_login_empty_credentials(self, client):
        """
        Test login with empty username and password
        """
        response = client.post('/login', data=dict(username='', password=''))
        assert response.status_code == 302
        assert 'Invalid credentials!' in session['_flashes'][0][1]

    def test_login_incorrect_type(self, client):
        """
        Test login with incorrect input types
        """
        response = client.post('/login', data=dict(username=123, password=456))
        assert response.status_code == 302
        assert 'Invalid credentials!' in session['_flashes'][0][1]

    def test_login_invalid_credentials(self, client_2):
        """
        Test login with invalid credentials.
        Expects a redirect to the index page and a flash message.
        """
        with app.test_request_context():
            response = client_2.post('/login', data={
                'username': 'nonexistent_user',
                'password': 'wrong_password'
            }, follow_redirects=True)

            assert response.status_code == 200
            assert b'Invalid credentials!' in response.data
            assert response.request.path == url_for('index')
            assert 'user' not in session

    def test_login_invalid_credentials_2(self, client):
        """
        Test login with invalid credentials
        """
        # Perform login with invalid credentials
        response = client.post('/login', data={
            'username': 'invaliduser',
            'password': 'invalidpass'
        }, follow_redirects=True)

        # Check if redirected to index page
        assert response.request.path == url_for('index')
        
        # Check if flash message is set
        assert b'Invalid credentials!' in response.data
        
        # Check if user is not in session
        with client.session_transaction() as sess:
            assert 'user' not in sess

    def test_login_invalid_credentials_3(self, client):
        """
        Test login with invalid username and password
        """
        response = client.post('/login', data=dict(username='nonexistent', password='wrongpass'))
        assert response.status_code == 302
        assert 'Invalid credentials!' in session['_flashes'][0][1]

    def test_login_missing_form_fields(self, client):
        """
        Test login with missing form fields
        """
        response = client.post('/login', data={})
        assert response.status_code == 400

    def test_login_sql_injection_attempt(self, client):
        """
        Test login with SQL injection attempt
        """
        injection = "' OR '1'='1"
        response = client.post('/login', data=dict(username=injection, password=injection))
        assert response.status_code == 302
        assert 'Invalid credentials!' in session['_flashes'][0][1]

    def test_login_successful(self, client):
        """
        Test successful login with valid credentials
        """
        # Set up test data
        with app.app_context():
            user = User(username='testuser', password='testpass')
            db.session.add(user)
            db.session.commit()

        # Perform login
        response = client.post('/login', data={
            'username': 'testuser',
            'password': 'testpass'
        }, follow_redirects=True)

        # Check if redirected to home page
        assert response.request.path == url_for('home')
        
        # Check if user is in session
        with client.session_transaction() as sess:
            assert sess['user'] == 'testuser'

        # Clean up test data
        with app.app_context():
            db.session.delete(user)
            db.session.commit()

    def test_login_successful_2(self, client):
        """
        Test successful login
        """
        with app.app_context():
            user = User(username='testuser', password='testpass')
            db.session.add(user)
            db.session.commit()

        response = client.post('/login', data=dict(username='testuser', password='testpass'))
        assert response.status_code == 302
        assert response.headers['Location'] == url_for('home', _external=True)
        with client.session_transaction() as sess:
            assert sess['user'] == 'testuser'

    def test_login_username_too_long(self, client):
        """
        Test login with username exceeding the maximum length
        """
        long_username = 'a' * 81  # Assuming max length is 80
        response = client.post('/login', data=dict(username=long_username, password='password'))
        assert response.status_code == 302
        assert 'Invalid credentials!' in session['_flashes'][0][1]

    def test_logout_redirects_to_index(self):
        """
        Test that logout removes the user from the session and redirects to index
        """
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = 'testuser'

            response = client.get('/logout')
            
            assert response.status_code == 302
            assert response.location == url_for('index', _external=True)
            
            with client.session_transaction() as sess:
                assert 'user' not in sess

    def test_logout_when_user_not_in_session(self):
        """
        Test logout when there's no user in the session.
        """
        with app.test_client() as client:
            with client.session_transaction() as sess:
                if 'user' in sess:
                    del sess['user']
            
            response = client.get('/logout')
            assert response.status_code == 302
            assert response.headers['Location'] == '/'
            with client.session_transaction() as sess:
                assert 'user' not in sess

    def test_logout_with_invalid_method(self):
        """
        Test logout with an invalid HTTP method.
        """
        with app.test_client() as client:
            response = client.post('/logout')
            assert response.status_code == 405

    def test_logout_with_invalid_session(self):
        """
        Test logout with an invalid session.
        """
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = None
            
            response = client.get('/logout')
            assert response.status_code == 302
            assert response.headers['Location'] == '/'
            with client.session_transaction() as sess:
                assert 'user' not in sess

    def test_logout_with_malformed_url(self):
        """
        Test logout with a malformed URL.
        """
        with app.test_client() as client:
            response = client.get('/logout/')  # Extra slash
            assert response.status_code == 404

    def test_logout_with_multiple_session_variables(self):
        """
        Test logout when there are multiple session variables.
        """
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = 'testuser'
                sess['other_var'] = 'some_value'
            
            response = client.get('/logout')
            assert response.status_code == 302
            assert response.headers['Location'] == '/'
            with client.session_transaction() as sess:
                assert 'user' not in sess
                assert 'other_var' in sess

    def test_purchases(self):
        """
        Test the purchases route when user is logged in.
        Verifies that the correct purchases are retrieved and rendered.
        """
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess['user'] = 'testuser'

            # Create test purchases
            test_purchases = [
                Purchase(username='testuser', place='Paris', package='premium', date='2023-07-01'),
                Purchase(username='testuser', place='London', package='budget', date='2023-08-15'),
            ]
            db.session.add_all(test_purchases)
            db.session.commit()

            # Make request to purchases route
            response = client.get('/purchases')

            # Check response
            assert response.status_code == 200
            assert b'Paris' in response.data
            assert b'London' in response.data
            assert b'premium' in response.data
            assert b'budget' in response.data
            assert b'2023-07-01' in response.data
            assert b'2023-08-15' in response.data

            # Clean up test data
            for purchase in test_purchases:
                db.session.delete(purchase)
            db.session.commit()

    def test_purchases_db_error(self, client_2, mocker):
        """
        Test purchases route when database query raises an exception
        """
        with client_2.session_transaction() as sess:
            sess['user'] = 'testuser'
        
        mocker.patch('app.Purchase.query.filter_by', side_effect=Exception('Database error'))
        
        response = client_2.get('/purchases')
        assert response.status_code == 500
        assert b'An error occurred while fetching purchases' in response.data

    def test_purchases_empty_session(self, client_2):
        """
        Test purchases route with an empty session
        """
        response = client_2.get('/purchases')
        assert response.status_code == 302
        assert response.location == '/'

    def test_purchases_invalid_user(self, client_2):
        """
        Test purchases route with an invalid user in the session
        """
        with client_2.session_transaction() as sess:
            sess['user'] = 'nonexistentuser'
        
        response = client_2.get('/purchases')
        assert response.status_code == 200
        assert b'No purchases found' in response.data

    def test_purchases_no_purchases(self, client_2):
        """
        Test purchases route when authenticated user has no purchases
        """
        with client_2.session_transaction() as sess:
            sess['user'] = 'testuser'
        
        response = client_2.get('/purchases')
        assert response.status_code == 200
        assert b'No purchases found' in response.data

    def test_purchases_unauthenticated(self, client_2):
        """
        Test purchases route when user is not authenticated
        """
        response = client_2.get('/purchases')
        assert response.status_code == 302
        assert response.location == '/'

    def test_register_renders_signup_template(self):
        """
        Test that the register route renders the signup.html template
        """
        # Create a test client
        client = app.test_client()

        # Send a GET request to the /register route
        response = client.get('/register')

        # Check that the response status code is 200 (OK)
        assert response.status_code == 200

        # Check that the rendered template is 'signup.html'
        with app.app_context():
            rendered_template = render_template('signup.html')
            assert response.data == rendered_template.encode('utf-8')

    def test_register_route_accessibility(self, client):
        """
        Test that the register route is accessible without authentication.
        """
        response = client.get('/register')
        assert response.status_code == 200
        assert b'signup.html' in response.data

    def test_register_route_content(self, client):
        """
        Test that the register route returns the expected content.
        """
        response = client.get('/register')
        assert b'<form' in response.data
        assert b'username' in response.data
        assert b'password' in response.data

    def test_register_route_returns_signup_template(self, client):
        """
        Test that the register route returns the signup.html template.
        """
        response = client.get('/register')
        assert response.status_code == 200
        assert b'signup.html' in response.data

    def test_register_route_unauthorized_access(self, client):
        """
        Test that accessing the register route when already logged in doesn't cause errors.
        """
        with client.session_transaction() as session:
            session['user'] = 'test_user'
        response = client.get('/register')
        assert response.status_code == 200
        assert b'signup.html' in response.data

    def test_register_with_get_method(self, client):
        """
        Test that the register route only accepts GET requests.
        """
        response = client.post('/register')
        assert response.status_code == 405

    def test_signup_2(self):
        """
        Test successful user signup when username doesn't exist
        """
        with app.test_client() as client:
            with app.app_context():
                # Clear the database
                db.drop_all()
                db.create_all()

                # Prepare test data
                username = "newuser"
                password = "password123"

                # Make a POST request to signup
                response = client.post('/signup', data={
                    'username': username,
                    'password': password
                }, follow_redirects=True)

                # Check if the user was added to the database
                user = User.query.filter_by(username=username).first()
                assert user is not None
                assert user.username == username
                assert user.password == password

                # Check if the response redirects to home page
                assert response.request.path == url_for('home')

                # Check if the user is in session
                with client.session_transaction() as session:
                    assert session['user'] == username

    def test_signup_empty_input(self, client):
        """
        Test signup with empty username and password
        """
        response = client.post('/signup', data={'username': '', 'password': ''}, follow_redirects=True)
        assert b'Username already exists!' not in response.data
        assert response.request.path == url_for('index')

    def test_signup_existing_user(self):
        """
        Test signup with an existing username.
        Expects a redirect to the index page with a flash message.
        """
        with app.test_client() as client:
            with app.app_context():
                # Create a test user
                test_user = User(username='testuser', password='testpass')
                db.session.add(test_user)
                db.session.commit()

                # Attempt to sign up with the same username
                response = client.post('/signup', data={
                    'username': 'testuser',
                    'password': 'newpassword'
                }, follow_redirects=True)

                # Check if the response is a redirect to the index page
                assert response.request.path == url_for('index')

                # Check if the flash message is present
                assert b'Username already exists!' in response.data

                # Clean up the test user
                db.session.delete(test_user)
                db.session.commit()

    def test_signup_existing_user_2(self, client):
        """
        Test signup with an existing username
        """
        # First, create a user
        client.post('/signup', data={'username': 'testuser', 'password': 'testpass'})
        
        # Try to create the same user again
        response = client.post('/signup', data={'username': 'testuser', 'password': 'newpass'}, follow_redirects=True)
        assert b'Username already exists!' in response.data
        assert response.request.path == url_for('index')

    def test_signup_incorrect_type(self, client):
        """
        Test signup with incorrect type for username and password
        """
        response = client.post('/signup', data={'username': 123, 'password': 456}, follow_redirects=True)
        assert b'Username already exists!' not in response.data
        assert response.request.path == url_for('index')

    def test_signup_invalid_input(self, client):
        """
        Test signup with invalid input (special characters in username)
        """
        response = client.post('/signup', data={'username': 'user@123', 'password': 'password'}, follow_redirects=True)
        assert b'Username already exists!' not in response.data
        assert response.request.path == url_for('index')

    def test_signup_long_username(self, client):
        """
        Test signup with username exceeding maximum length
        """
        long_username = 'a' * 81  # Assuming max length is 80
        response = client.post('/signup', data={'username': long_username, 'password': 'password'}, follow_redirects=True)
        assert b'Username already exists!' not in response.data
        assert response.request.path == url_for('index')

    def test_signup_sql_injection(self, client):
        """
        Test signup with potential SQL injection in username
        """
        response = client.post('/signup', data={'username': "'; DROP TABLE users; --", 'password': 'password'}, follow_redirects=True)
        assert b'Username already exists!' not in response.data
        assert response.request.path == url_for('index')
        
        # Verify that the users table still exists
        with app.app_context():
            assert User.query.first() is not None

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    client = app.test_client()

    with app.app_context():
        db.create_all()

    yield client

    with app.app_context():
        db.drop_all()