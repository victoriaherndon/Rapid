document.addEventListener("DOMContentLoaded", () => {
    console.log("JS loaded!");

    // FORM VALIDATION 
    document.getElementById("createAccountForm").addEventListener("submit", function (event) {
        const username = document.getElementById("username").value.trim();
        const email = document.getElementById("email").value.trim();
        const password = document.getElementById("password").value;
        const confirmPassword = document.getElementById("confirmPassword").value;

        // USERNAME VALIDATION
        if (username.length < 5 || username.length > 20) {
            alert("Username must be between 5 and 20 characters.");
            const usernameRequirements = document.getElementById("usernameRequirements");
            usernameRequirements.classList.add("invalid");
            usernameRequirements.classList.remove("valid");
            usernameRequirements.style.color = "red";
            event.preventDefault();
            return;
        }

        // PASSWORD VALIDATION
        const lengthReq = document.getElementById("length").classList.contains("valid");
        const uppercaseReq = document.getElementById("uppercase").classList.contains("valid");
        const lowercaseReq = document.getElementById("lowercase").classList.contains("valid");
        const numberReq = document.getElementById("number").classList.contains("valid");
        const specialReq = document.getElementById("special").classList.contains("valid");

        if (!(lengthReq && uppercaseReq && lowercaseReq && numberReq && specialReq)) {
            alert("Password does not meet all requirements.");
            event.preventDefault();
            return;
        }

        if (password !== confirmPassword) {
            alert("Passwords do not match.");
            event.preventDefault();
            return;
        }

        sessionStorage.setItem("showLoginModal", "true");
    });

    // PASSWORD REQUIREMENTS LIVE VALIDATION
    const passwordInput = document.getElementById("password");
    const length = document.getElementById("length");
    const uppercase = document.getElementById("uppercase");
    const lowercase = document.getElementById("lowercase");
    const number = document.getElementById("number");
    const special = document.getElementById("special");

    const requirements = [
        { regex: /.{8,}/, element: length },
        { regex: /[A-Z]/, element: uppercase },
        { regex: /[a-z]/, element: lowercase },
        { regex: /[0-9]/, element: number },
        { regex: /[!@#$%^&*]/, element: special }
    ];

    passwordInput.addEventListener("focus", () => {
        document.getElementById("passwordRequirements").style.display = "block";
    });

    passwordInput.addEventListener("blur", () => {
        document.getElementById("passwordRequirements").style.display = "none";
    });

    passwordInput.addEventListener("input", () => {
    const password = passwordInput.value; 


    requirements.forEach(req => {
        if (req.regex.test(password)) {
            req.element.classList.add("valid");
            req.element.classList.remove("invalid");
        } else {
            req.element.classList.add("invalid");
            req.element.classList.remove("valid");
        }
    });
});


    // USERNAME LIVE VALIDATION 
    const usernameInput = document.getElementById("username");
    const usernameRequirements = document.getElementById("usernameRequirements");

    usernameRequirements.style.display = "none";

    usernameInput.addEventListener("focus", () => {
        usernameRequirements.style.display = "block";
    });

    usernameInput.addEventListener("input", () => {
        const username = usernameInput.value.trim();
        if (username.length >= 5 && username.length <= 20) {
            usernameRequirements.classList.add("valid");
            usernameRequirements.classList.remove("invalid");
            usernameRequirements.style.color = "green";
        } else {
            usernameRequirements.classList.add("invalid");
            usernameRequirements.classList.remove("valid");
            usernameRequirements.style.color = "red";
        }
    });

    usernameInput.addEventListener("blur", () => {
        usernameRequirements.style.display = "none";
    });
});
