from django.urls import path
from . import views
from django.contrib.auth import views as auth_views


urlpatterns = [
    path('', views.user_login, name='login'),
    path('dashboard', views.dashboard, name='dashboard'),
    path('logout',views.doLogout,name='logout'),
    path('profile/', views.profile, name='profile'),
    path('delete_user/<str:id>',views.delete_user,name='delete_user'),
    path('profile_update', views.profile_update, name='profile_update'),
    path('userview/>',views.View_User,name='view_user'),
    path('userview/<int:id>',views.View_User,name='view_user'),
    path('password_change/', views.change_password, name='password_change'),
    path("password_reset/", views.password_reset, name="password_reset"),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', views.confirm_password, name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='password_reset_complete.html'), name='password_reset_complete'),
    path('signup/', views.signup, name = 'signup'),
    path('employee_form', views.employee_form, name='employee_form'),
    path('delete_employee<str:id>',views.delete_city,name="delete_employee"),
    
    
    
    
]
