document.addEventListener('DOMContentLoaded', function() {
    var savedPassword = '';

    function showMsg(type, text) {
        var b = document.getElementById('msg-box');
        b.className = 'msg ' + type + ' visible';
        b.textContent = text;
    }
    function clearMsg() {
        var b = document.getElementById('msg-box');
        b.className = 'msg';
        b.textContent = '';
    }
    function parseError(data) {
        if (!data.detail) return 'Request failed';
        if (typeof data.detail === 'string') return data.detail;
        if (data.detail.error) return data.detail.error;
        if (Array.isArray(data.detail)) return data.detail.map(function(d){ return d.msg; }).join(', ');
        return JSON.stringify(data.detail);
    }

    // Step 1: Login
    document.getElementById('login-form').addEventListener('submit', async function(e) {
        e.preventDefault();
        clearMsg();
        var btn = document.getElementById('login-btn');
        btn.disabled = true;
        btn.textContent = 'Authenticating...';

        try {
            var resp = await fetch('/auth/login', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    username: document.getElementById('username').value,
                    password: document.getElementById('password').value,
                    totp_code: document.getElementById('totp_code').value
                })
            });
            var data = await resp.json();
            if (resp.ok) {
                if (data.force_password_change) {
                    savedPassword = document.getElementById('password').value;
                    document.getElementById('login-form').className = 'hidden';
                    document.getElementById('pw-form').className = '';
                    document.getElementById('page-subtitle').textContent = 'Set a new password to continue';
                    showMsg('info', 'First login \u2014 you must change your password before continuing.');
                } else {
                    var params = new URLSearchParams(window.location.search);
                    var next = params.get('next');
                    window.location.href = next && next.startsWith('/') && !next.startsWith('//') ? next : '/';
                }
            } else {
                showMsg('error', parseError(data));
            }
        } catch (err) {
            showMsg('error', 'Connection error: ' + err.message);
        } finally {
            btn.disabled = false;
            btn.textContent = 'Sign In';
        }
    });

    // Step 2: Password Change
    document.getElementById('pw-form').addEventListener('submit', async function(e) {
        e.preventDefault();
        clearMsg();
        var newPw = document.getElementById('new_password').value;
        var confirmPw = document.getElementById('confirm_password').value;

        if (newPw.length < 36) { showMsg('error', 'Password must be at least 36 characters.'); return; }
        if (newPw !== confirmPw) { showMsg('error', 'Passwords do not match.'); return; }

        var btn = document.getElementById('pw-btn');
        btn.disabled = true;
        btn.textContent = 'Changing...';

        try {
            var resp = await fetch('/auth/password/change', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    current_password: savedPassword,
                    new_password: newPw
                })
            });
            var data = await resp.json();
            if (resp.ok) {
                document.getElementById('pw-form').className = 'hidden';
                showMsg('success', 'Password changed. Please sign in with your new password.');
                document.getElementById('page-subtitle').textContent = 'Sign in to continue';
                document.getElementById('login-form').className = '';
                document.getElementById('password').value = '';
                document.getElementById('totp_code').value = '';
                document.getElementById('username').focus();
            } else {
                showMsg('error', parseError(data));
            }
        } catch (err) {
            showMsg('error', 'Connection error: ' + err.message);
        } finally {
            btn.disabled = false;
            btn.textContent = 'Change Password';
        }
    });
});
