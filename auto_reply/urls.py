from django.urls import path

from . import views

urlpatterns = [
    path('signup/', views.signup, name='signup'),
    path('', views.rules_dashboard, name='rules_dashboard'),
    path('rules/', views.rules_list, name='rules_list'),
    path('rule/create/', views.rule_create, name='rule_create'),
    path('rule/create-ui/', views.rule_create_ui, name='rule_create_ui'),
    path('rule/<int:rule_id>/edit/', views.rule_edit, name='rule_edit'),
    path('rule/<int:rule_id>/edit-ui/', views.rule_edit_ui, name='rule_edit_ui'),
    path('rule/<int:rule_id>/toggle/', views.rule_toggle, name='rule_toggle'),
    path('rule/<int:rule_id>/delete/', views.rule_delete, name='rule_delete'),
    path('save_rule/', views.save_rule, name='save_rule'),
    path('gmail/auth/', views.gmail_auth, name='gmail_auth'),
    path('gmail/callback/', views.gmail_callback, name='gmail_callback'),
    # Gmail API connect/disconnect (separate from app login)
    path('gmail/pull/', views.gmail_pull, name='gmail_pull'),
    # Testing endpoint to evaluate a rule against a sample email and optionally send a reply
    path('rules/test-fire/', views.test_fire, name='test_fire'),
    # API endpoint for Cloudinary API key management (GET/POST in one view)
    path('api/user/cloudinary-key/', views.cloudinary_api_key_view, name='cloudinary_api_key'),

]