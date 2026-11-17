from django import forms

class LogUploadForm(forms.Form):
    log_file = forms.FileField(label='Select Log File')
    log_type = forms.ChoiceField(
        choices=[('AUTH', 'Authentication'), ('FIREWALL', 'Firewall'), ('NETWORK', 'Network')],
        widget=forms.Select(attrs={'class': 'form-control'})
    )
