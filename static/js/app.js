document.addEventListener('DOMContentLoaded', function () {
    // Sign In and Sign Up Modals
    const signinModal = document.getElementById('signin-modal');
    const signupModal = document.getElementById('signup-modal');
    const signinButton = document.getElementById('signin-button');
    const signupButton = document.getElementById('signup-button');
    const closeSignin = document.getElementById('close-signin'); // Add close buttons to modals
    const closeSignup = document.getElementById('close-signup');

    if (signinButton && signupButton && signinModal && signupModal) {
        // Open sign-in modal and hide sign-up modal
        signinButton.addEventListener('click', function() {
            const signinModalInstance = new bootstrap.Modal(signinModal);
            signinModalInstance.show();
            const signupModalInstance = bootstrap.Modal.getInstance(signupModal);
            if (signupModalInstance) {
                signupModalInstance.hide();
            }
        });

        // Open sign-up modal and hide sign-in modal
        signupButton.addEventListener('click', function() {
            const signupModalInstance = new bootstrap.Modal(signupModal);
            signupModalInstance.show();
            const signinModalInstance = bootstrap.Modal.getInstance(signinModal);
            if (signinModalInstance) {
                signinModalInstance.hide();
            }
        });

        // Close sign-in modal on close button click
        closeSignin.addEventListener('click', function() {
            const signinModalInstance = bootstrap.Modal.getInstance(signinModal);
            if (signinModalInstance) {
                signinModalInstance.hide();
            }
        });

        // Close sign-up modal on close button click
        closeSignup.addEventListener('click', function() {
            const signupModalInstance = bootstrap.Modal.getInstance(signupModal);
            if (signupModalInstance) {
                signupModalInstance.hide();
            }
        });

        // Close the modal if the user clicks outside of the modal content (not the modal itself)
        window.addEventListener('click', function(event) {
            if (event.target === signinModal) {
                const signinModalInstance = bootstrap.Modal.getInstance(signinModal);
                if (signinModalInstance) {
                    signinModalInstance.hide();
                }
            }
            if (event.target === signupModal) {
                const signupModalInstance = bootstrap.Modal.getInstance(signupModal);
                if (signupModalInstance) {
                    signupModalInstance.hide();
                }
            }
        });
    }

    // State and LGA Selectors
    const stateSelect = document.getElementById('hospital-state');
    const lgaSelect = document.getElementById('hospital-local-government');

    enlist_hospital = document.getElementById('enlist_hospital')

    enlist_hospital.addEventListener('click', function (){
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

        
    })

    stateSelect.addEventListener('change', function () {
        const selectedState = stateSelect.value;
        console.log(selectedState)
        lgaSelect.innerHTML = '';

        fetch(`/api/lgas/${selectedState}`)
            .then(response => response.json())
            .then(lgas => {
                console.log(lgas)
                if (lgas.error) {
                    alert(lgas.error);
                } else {
                    lgas.forEach(lga => {
                        const option = document.createElement('option');
                        option.value = lga.name;
                        option.textContent = lga.name;
                        lgaSelect.appendChild(option);
                    });
                }
            });
    });
        
    

    // Filters Form
    const filtersForm = document.getElementById('filters-form');
    if (filtersForm) {
        filtersForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const gender = document.getElementById('gender-filter').value;
            const ageGroup = document.getElementById('age-filter').value;

            console.log('Selected Gender:', gender);
            console.log('Selected Age Group:', ageGroup);
        });
    }


    // Enlist Dropdown Menu
    const enlistButton = document.querySelector('.nav-item.dropdown .nav-link.dropdown-toggle');
    const dropdownMenu = document.querySelector('.nav-item.dropdown .dropdown-menu');

    if (enlistButton && dropdownMenu) {
        enlistButton.addEventListener('click', function() {
            const isVisible = dropdownMenu.classList.contains('show');
            dropdownMenu.classList.toggle('show', !isVisible);
        });
    }

    // Handle Public and Private Hospital Selection
    const publicHospitalButton = document.querySelector('.dropdown-menu .dropdown-item[data-hospital-type="public"]');
    const privateHospitalButton = document.querySelector('.dropdown-menu .dropdown-item[data-hospital-type="private"]');

    if (publicHospitalButton) {
        publicHospitalButton.addEventListener('click', function() {
            // Open the modal for hospital enlistment
            const enlistHospitalModal = new bootstrap.Modal(document.getElementById('enlistHospitalModal'));
            enlistHospitalModal.show();
            // Set hidden input to indicate public hospital
            document.getElementById('hospital-type').value = 'public';
        });
    }

    if (privateHospitalButton) {
        privateHospitalButton.addEventListener('click', function() {
            // Open the modal for hospital enlistment
            const enlistHospitalModal = new bootstrap.Modal(document.getElementById('enlistHospitalModal'));
            enlistHospitalModal.show();
            // Set hidden input to indicate private hospital
            document.getElementById('hospital-type').value = 'private';
        });
    }

    // // ChatGPT Integration
    // const chatboxContainer = document.createElement('div');
    // chatboxContainer.id = 'chatbox-container';
    // chatboxContainer.innerHTML = `
    //     <div id="chatbox">
    //         <div id="chat-messages"></div>
    //         <input type="text" id="chat-input" placeholder="Type your message...">
    //         <button id="send-chat">Send</button>
    //     </div>
    // `;
    // document.body.appendChild(chatboxContainer);

    const chatMessages = document.getElementById('chat-messages');
    const chatInput = document.getElementById('chat-input');
    const sendChatButton = document.getElementById('send-chat');

    sendChatButton.addEventListener('click', async function() {
        const userMessage = chatInput.value;
        if (userMessage.trim() === '') return;

        // Display user message
        chatMessages.innerHTML += `<div>User: ${userMessage}</div>`;
        chatInput.value = '';

        try {
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ message: userMessage })
            });

            const data = await response.json();
            const botReply = data.reply;

            // Display ChatGPT's response
            chatMessages.innerHTML += `<div>ChatGPT: ${botReply}</div>`;
            chatMessages.scrollTop = chatMessages.scrollHeight;
        } catch (error) {
            console.error('Error:', error);
            chatMessages.innerHTML += `<div>Error: Could not send message. Please try again later.</div>`;
        }
    });
});
