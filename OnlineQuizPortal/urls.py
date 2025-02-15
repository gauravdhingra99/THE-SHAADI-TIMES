"""OnlineQuizPortal URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from django.urls import path,include
from login import views
urlpatterns = [
    path('admin/', admin.site.urls),
    path('welcome/', views.home, name='home'),
    url(r"^activate/b'(?P<uidb64>[0-9A-Za-z_\-]+)'/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$", views.activate,name='activate'),
    path('signup/',views.signup,name='signup'),
    path('login/',views.login,name='login'),

]
