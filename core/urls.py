from django.urls import path
from . import views

urlpatterns = [
    path('fetch-image/', views.fetch_image, name='fetch_image'),
]