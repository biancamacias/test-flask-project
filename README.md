## How to run test project

In order to run this test project, your development environment must be set up properly in order to run the site
locally without errors. There are a few things you must install.

*This setup assumes you are running the project in a Linux environment.*

1. Clone this repository.
```shell
$ git clone https://github.com/biancamacias/test-flask-project.git
```

2. Follow the installation process outlined [here](https://flask.palletsprojects.com/en/2.1.x/installation/).

```shell
$ cd test-flask-project
$ python3 -m venv venv
```

3. Activate the virtual environment.

```shell
$ source venv/bin/activate
```

4. Install all the necessary requirements.
```shell
$ pip install -r requirements.txt
```

5. Assuming you have a GCP project, [create an OAuth 2.0 Client ID](https://developers.google.com/identity/protocols/oauth2/openid-connect#appsetup) (if you haven't already). 
6. **Set the redirect URI to be** `http://127.0.0.1:5000/callback`.
7. Download the JSON file generated after creating the client ID and take note of the file path in the project. 
You can simply add it to the repository. *Note: do not push this JSON file to any repository publicly. Keep client secrets a secret.*

8. Go through any `TODO` in `app.py` and set them accordingly, such as the path of the downloaded JSON file.

9. Run the project. Click the generated local address Flask gives in the terminal where you can test it in your browser.
```shell
$ flask run
```

## User Journey

1. Login through `index.html` page, which redirects user to login with their Google/Gmail credentials.
![index](https://user-images.githubusercontent.com/51244558/172948692-4388a306-3206-4143-a985-2e470362b9d1.png)

2. Choose account.
![login](https://user-images.githubusercontent.com/51244558/172948780-f77ab644-51bd-42c6-8502-1bb44e7b3289.png)

3. View `home.html` and logout.
![home](https://user-images.githubusercontent.com/51244558/172948825-80e6ccbf-e59b-4200-8059-87f28db916dc.png)

