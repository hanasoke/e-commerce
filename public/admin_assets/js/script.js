function togglePassword(inputId, iconSpan) {
    const input = document.getElementById(inputId);
    const icon = iconSpan.querySelector('.passwordeyes');

    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    }
}

document.addEventListener("DOMContentLoaded", function () {
    const emailInput = document.getElementById("login_email");
    const rememberCheckbox = document.getElementById("remember");

    // Store the initial remembered value from the field
    const originalEmail = emailInput.value.trim();

    emailInput.addEventListener("input", function () {
        const currentEmail = emailInput.value.trim();

        if (currentEmail !== originalEmail) {
            rememberCheckbox.checked = false;
        }
    });
});