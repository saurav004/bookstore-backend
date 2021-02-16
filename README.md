# ParkingLot

# install all the required packages from requirements.txt


# django-project

## Setup

### Install Django:
```bash
pip install Django
```

### Install requirements:(in shell)
```bash
pip install -r requirements.txt
```

### Perform database migration:
```bash
python manage.py check
python manage.py migrate
```

## Run Development Server

```bash
python manage.py runserver
```
Public endpoint is at http://localhost:8000/api/

Admin endpoint is at http://127.0.0.1:8000/admin/, `user: admin`, `password: qazwsxedc`

## Testing

### Run tests:
```bash
python manage.py test
```

```bash
Creating test database for alias 'default'...
System check identified no issues (0 silenced).
..........
----------------------------------------------------------------------
Ran 10 tests in 0.025s

OK
Destroying test database for alias 'default'...
```
