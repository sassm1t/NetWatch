from django.contrib import admin
from django.urls import path,include
from . import views

urlpatterns = [
    path('', views.my_view,name = "home"),
    # path("__reload__/", include("django_browser_reload.urls")),
]
