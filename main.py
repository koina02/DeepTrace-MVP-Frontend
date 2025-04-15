from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from cyberguard import authenticate_master, encrypt_file, decrypt_file

class CyberGuardUI(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", **kwargs)
        self.label = Label(text="Enter Master Password")
        self.password_input = TextInput(password=True, multiline=False)
        self.auth_button = Button(text="Authenticate")
        self.auth_button.bind(on_press=self.authenticate)
        
        self.add_widget(self.label)
        self.add_widget(self.password_input)
        self.add_widget(self.auth_button)

    def authenticate(self, instance):
        password = self.password_input.text
        if authenticate_master(password):
            self.label.text = "Authentication Successful!"
        else:
            self.label.text = "Invalid Password!"

class CyberGuardApp(App):
    def build(self):
        return CyberGuardUI()

if __name__ == "__main__":
    CyberGuardApp().run()
