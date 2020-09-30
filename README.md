# PhishThis

Ever get excessively bothered by the test phishing emails that InfoSec sends to educate you and your co-workers?
PhishThis is here to help. PhishThis will watch your gmail inbox and detect when a test phishing email is received. Once detected, PhishThis will delete the email from your inbox and forward a copy back to the InfoSec team making it appear you are exceptionally vigilant.

PhishThis uses the X-PHISHTEST header to detect emails sent by KnowBe4

## Deploying to Heroku
You can deploy your own copy of the app using this button:

[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.png)](https://dashboard.heroku.com/new?template=https%3A%2F%2Fgithub.com%2Fshopeonarope%2Fphishthis)

You'll need to verify your Heroku account to get enough [free](https://www.heroku.com/free) hours per month to run this 24/7.

----------------
Most of the imap work is ripped off from [Gprowl](https://github.com/chriscannon/Gprowl) with the author's permission.
