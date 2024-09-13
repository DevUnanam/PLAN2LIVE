document.addEventListener('DOMContentLoaded', function () {
    const signinModal = document.getElementById('signin-modal');
    const signupModal = document.getElementById('signup-modal');
    const signinButton = document.getElementById('signin-button');
    const signupButton = document.getElementById('signup-button');

    signinButton.addEventListener('click', function() {
        signinModal.style.display = 'block';
        signupModal.style.display = 'none';
    });

    signupButton.addEventListener('click', function() {
        signupModal.style.display = 'block';
        signinModal.style.display = 'none';
    });

    window.addEventListener('click', function(event) {
        if (event.target === signinModal || event.target === signupModal) {
            signinModal.style.display = 'none';
            signupModal.style.display = 'none';
        }
    });

    const stateSelect = document.getElementById('state-select');
    const lgaSelect = document.getElementById('lga-select');

    fetch('/api/states')
        .then(response => response.json())
        .then(states => {
            states.forEach(state => {
                const option = document.createElement('option');
                option.value = state;
                option.textContent = state;
                stateSelect.appendChild(option);
            });
        });

    stateSelect.addEventListener('change', function () {
        const selectedState = stateSelect.value;
        lgaSelect.innerHTML = '';

        fetch(`/api/lgas/${selectedState}`)
            .then(response => response.json())
            .then(lgas => {
                if (lgas.error) {
                    alert(lgas.error);
                } else {
                    lgas.forEach(lga => {
                        const option = document.createElement('option');
                        option.value = lga;
                        option.textContent = lga;
                        lgaSelect.appendChild(option);
                    });
                }
            });
    });

    document.getElementById('filters-form').addEventListener('submit', function(event) {
        event.preventDefault();
        const gender = document.getElementById('gender-filter').value;
        const ageGroup = document.getElementById('age-filter').value;

        console.log('Selected Gender:', gender);
        console.log('Selected Age Group:', ageGroup);
    });

    document.getElementById('hospital-state').addEventListener('change', function() {
        const stateName = this.value;

        fetch(`/api/lgas/${stateName}`)
            .then(response => response.json())
            .then(data => {
                const lgaSelect = document.getElementById('hospital-local-government');
                lgaSelect.innerHTML = '';

                if (data.error) {
                    alert(data.error);
                } else {
                    data.forEach(lga => {
                        const option = document.createElement('option');
                        option.value = lga;
                        option.textContent = lga;
                        lgaSelect.appendChild(option);
                    });
                }
            })
            .catch(error => {
                console.error('Error fetching LGAs:', error);
                alert('Unable to fetch LGAs. Please try again later.');
            });
    });

    document.getElementById('enlist-button').addEventListener('click', function() {
        const dropdownMenu = document.getElementById('dropdown-menu');
        dropdownMenu.style.display = dropdownMenu.style.display === 'block' ? 'none' : 'block';
    });

    document.getElementById('public-hospital').addEventListener('click', function() {
        document.getElementById('dropdown-menu').style.display = 'none';
        document.getElementById('enlist-form').style.display = 'block';
    });

    document.getElementById('private-hospital').addEventListener('click', function() {
        document.getElementById('dropdown-menu').style.display = 'none';
        document.getElementById('enlist-form').style.display = 'block';
    });
});
