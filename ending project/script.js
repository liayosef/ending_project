// מעבר בין טפסי התחברות והרשמה
document.addEventListener('DOMContentLoaded', function() {
    const showRegisterBtn = document.getElementById('showRegister');
    const showLoginBtn = document.getElementById('showLogin');
    const loginForm = document.getElementById('loginForm');
    const registerForm = document.getElementById('registerForm');

    if (showRegisterBtn) {
        showRegisterBtn.addEventListener('click', function() {
            loginForm.classList.add('hidden');
            registerForm.classList.remove('hidden');
        });
    }

    if (showLoginBtn) {
        showLoginBtn.addEventListener('click', function() {
            registerForm.classList.add('hidden');
            loginForm.classList.remove('hidden');
        });
    }

    // טיפול בטופס הרשמה
    const registerFormElement = document.getElementById('registerFormElement');
    if (registerFormElement) {
        registerFormElement.addEventListener('submit', function(event) {
            event.preventDefault();

            const fullName = document.getElementById('fullName').value;
            const email = document.getElementById('registerEmail').value;
            const password = document.getElementById('registerPassword').value;
            const confirmPassword = document.getElementById('confirmPassword').value;

            // איפוס הודעות שגיאה
            document.getElementById('passwordError').textContent = '';
            document.getElementById('confirmPasswordError').textContent = '';

            // וידוא תקינות הסיסמה
            if (password.length < 6) {
                document.getElementById('passwordError').textContent = 'הסיסמה חייבת להכיל לפחות 6 תווים';
                return;
            }

            // וידוא התאמת סיסמאות
            if (password !== confirmPassword) {
                document.getElementById('confirmPasswordError').textContent = 'הסיסמאות אינן תואמות';
                return;
            }

            // הצגת הודעת הצלחה
            document.getElementById('successMessage').textContent = 'ההרשמה בוצעה בהצלחה!';

            // איפוס הטופס
            document.getElementById('fullName').value = '';
            document.getElementById('registerEmail').value = '';
            document.getElementById('registerPassword').value = '';
            document.getElementById('confirmPassword').value = '';

            // מעבר לדף התחברות אחרי 2 שניות
            setTimeout(() => {
                registerForm.classList.add('hidden');
                loginForm.classList.remove('hidden');
                document.getElementById('successMessage').textContent = '';
            }, 2000);
        });
    }
});