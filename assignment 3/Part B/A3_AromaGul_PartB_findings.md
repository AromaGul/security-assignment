# Part B — Findings, full requests and Autorize comparison

Target: OWASP Juice Shop on 127.0.0.1:3000.
Roles: Anonymous, alice (customer, UserId 26), bob (customer, UserId 27), admin (UserId 1).
A fifth role exists: row 24 (`/rest/order-history/orders`) returns 403 even to admin, so there is a separate accounting role I did not have an account for.

Every FAIL is against the EXPECTED value I wrote before testing.

---

## 1. Two-line finding for every FAIL

### Missing authentication (anonymous gets data or can write)

**Row 4: `PUT /api/Products/1` (anon, alice, bob FAIL)**
Anonymous, alice and bob all got 200 when changing product 1's description. No token is needed to edit the catalogue.
Impact: anyone on the internet can change product names, descriptions and prices shown to every customer.

**Row 30: `GET /rest/admin/application-configuration` (anon, alice, bob FAIL)**
All roles got 200 with the full 36 KB configuration, despite the `/rest/admin/` path.
Impact: the whole application configuration is public, which gives an attacker a map of features and settings.

**Row 31: `GET /rest/admin/application-version` (anon, alice, bob FAIL)**
All roles got 200 with the version string.
Impact: version disclosure lets an attacker look up known vulnerabilities for that exact release.

**Row 32: `GET /api/Quantitys` (anon, alice, bob FAIL)**
All roles got 200 with stock levels for every product (7.6 KB).
Impact: internal inventory data is public.

**Row 34: `GET /ftp` (all four roles FAIL)**
Every role, including anonymous, got 200 with an HTML directory listing.
Impact: internal files are browsable by anyone. Expected 403 for every role, admin included.

**Row 35: `GET /metrics` (all four roles FAIL)**
Every role got 200 with Prometheus metrics (about 26 KB).
Impact: server internals, request counts and runtime details are exposed to anyone.

**Row 36: `GET /api/Recycles/{id}` (anon, alice FAIL)**
With no token, `/api/Recycles/10` returned bob's record (UserId 27, AddressId 11). As alice, ids 1, 2, 3 and 8 returned records of UserIds 2, 3, 4 and 1 (admin).
Impact: anyone can walk the ids and read every customer's recycling request and address reference. The list endpoint `/api/Recycles` is disabled, which gives a false sense that the data is protected.

**Row 27: `GET /api/Deliverys` (anon FAIL)**
Anonymous got 200 with the delivery options.
Impact: low. The data is delivery prices, but the endpoint was expected to need a login.

**Row 22: `GET /api/Recycles` (anon FAIL on status only)**
Anonymous got 200 instead of 401, but the body is `{"err":"Sorry, this endpoint is not supported."}`, so no data came back.
Impact: none on its own. Recorded as a status mismatch, not a data leak.

### Vertical (customer reaches admin-only data)

**Row 6: `GET /api/Users` (alice, bob FAIL)**
Both customers got 200 with the full user list (7.4 KB).
Impact: any customer can list every account, including emails and roles.

**Row 9: `GET /rest/user/authentication-details/` (alice, bob FAIL)**
Both customers got 200 with every user's details (9.6 KB). In the browser, alice is shown "403 You are not allowed to access this page" on `/#/administration`.
Impact: the 403 is only in the Angular front end. The API behind the admin page is open to every logged-in user.

**Row 21: `GET /api/Complaints` (alice, bob FAIL)**
As alice, the response contained complaints from UserId 3, 27 (bob) and 26 (her own).
Impact: customers can read other customers' support complaints, which may contain personal or order details.

### Horizontal (one customer reaches another's data)

**Row 7: `GET /api/Users/27` (alice FAIL)**
Alice got 200 with bob's user record.
Impact: any customer can read any other customer's account record by id.

**Rows 10 and 11: `GET /rest/basket/{id}` (bob on 6, alice on 7 FAIL)**
Bob read alice's basket (id 6) and alice read bob's basket (id 7), both 200 with data. Basket ids are small sequential numbers that are also inside each user's JWT (`bid`).
Impact: any customer can view any other customer's basket. Juice Shop also marked its "View Basket" challenge as solved.

**Row 15: `PUT /api/Addresss/{id}` (alice, admin FAIL)**
As alice, `PUT /api/Addresss/10` with `{"city":"AliceWasHere"}` returned 200, changed bob's address and reassigned its UserId from 27 to 26.
Impact: any customer can overwrite and take ownership of another customer's saved address, so deliveries can be redirected and the address disappears from the victim's account.

### Error handling

**Row 23: `GET /rest/order-history` (anon FAIL)**
Anonymous got 500 with an HTML error page instead of 401.
Impact: unhandled error leaks stack or framework detail. Juice Shop marked its "Error Handling" challenge as solved.

### Expectation mismatches (not vulnerabilities)

**Rows 10 and 11 (admin FAIL)**
Admin can read any customer's basket. I expected owner-only. This may be an intended support capability, so it is a design question for the client rather than a confirmed vulnerability.

**Row 24: `GET /rest/order-history/orders` (admin FAIL)**
Admin got 403. The endpoint needs the accounting role, so my expectation was wrong, not the application.

**Row 26: `GET /rest/deluxe-membership` (admin FAIL)**
Admin got 400. Deluxe membership is a customer feature. My expectation was wrong.

I have left these as FAIL rather than editing the EXPECTED column after the fact.

---

## 2. Full requests (three)

Tokens are truncated.

### Full request 1: Row 15, address takeover (horizontal write)

```
PUT /api/Addresss/10 HTTP/1.1
Host: 127.0.0.1:3000
Authorization: Bearer eyJ0eXAiOiJKV1Qi...<alice, UserId 26, truncated>
Cookie: token=eyJ0eXAiOiJKV1Qi...<truncated>
Content-Type: application/json

{"city":"AliceWasHere"}
```

Response: `200 OK`

```
{"status":"success","data":{"UserId":26,"id":10,"fullName":"Bob","streetAddress":"Flat 214","city":"AliceWasHere", ...}}
```

Address 10 belonged to bob (UserId 27) before the request.

### Full request 2: Row 21, every user's complaints

```
GET /api/Complaints/ HTTP/1.1
Host: 127.0.0.1:3000
Authorization: Bearer eyJ0eXAiOiJKV1Qi...<alice, UserId 26, truncated>
Cookie: token=eyJ0eXAiOiJKV1Qi...<truncated>
Accept: application/json, text/plain, */*
```

Response: `200 OK`

```
{"status":"success","data":[
 {"UserId":3,"id":1, ...},
 {"UserId":27,"id":2,"message":"bob's complain", ...},
 {"UserId":26,"id":3,"message":"alice complain", ...}]}
```

### Full request 3: Row 36, recycling record with no login

```
GET /api/Recycles/10 HTTP/1.1
Host: 127.0.0.1:3000
Accept: application/json, text/plain, */*
Cookie: language=en; cookieconsent_status=dismiss
```

No Authorization header and no token cookie.

Response: `200 OK`

```
{"status":"success","data":[{"UserId":27,"AddressId":11,"id":10,"quantity":192,"isPickup":false, ...}]}
```

The same request returned an identical body (same ETag `bc-RMMA3D...`) as anon, alice, bob and admin, which shows the server does not check identity at all.

---

## 3. Autorize comparison

Setup: Autorize with User 1 = alice's token, User 2 = a second customer account's token, and "Check unauthenticated" on. I browsed every page as admin, then as bob.

### What Autorize caught that I missed

- `GET /api/BasketItems/9`: alice got the same response length as bob (155 B), flagged Bypassed. My matrix tested whole baskets, not single basket items.
- `PUT /api/BasketItems/9`: alice's replay of bob's quantity change was flagged Bypassed. This would be a cross-account write.
- `GET /rest/basket/1`: both customer accounts (User 1 and User 2) got the admin's basket (1994 B). I had only tested customer-to-customer.

I added the first two as rows 37 and 38. I did not confirm them by hand, so they are recorded as UNVERIFIED leads, not findings. Autorize only compares response length and content, so a manual check is needed before reporting them.

### What I caught that Autorize missed

Autorize only replays requests the browser actually sends, so it never saw:

- Row 15, address takeover: the UI never edits another user's address. I had to craft the request.
- Row 36, `/api/Recycles/{id}` with no login: the UI never fetches a single recycling record.
- Row 21, `GET /api/Complaints`: the complaint page only POSTs.
- Row 7, `/api/Users/27`: the UI never requests another user's record by id.
- Row 4, anonymous product edit: nobody edits products through the UI.
- Rows 34 and 35 (`/ftp`, `/metrics`): not linked from any page. They do not appear in the Burp sitemap either.

`/api/Users` (row 6) and `/api/Quantitys` (row 32) appear in the Burp sitemap, so the browser requested them at some point. I tested both directly with all four roles, so they are covered in the matrix whether or not Autorize replayed them.

### Where Autorize was wrong

- Public endpoints flagged Bypassed: `/api/Feedbacks`, `/rest/products/{id}/reviews`, `/api/Products/{id}`, `/api/Challenges`. Everyone is meant to see these. Autorize has no EXPECTED column, so it cannot know.
- Identical empty responses flagged Bypassed: `/rest/user/whoami` (11 B, `{"user":{}}`), and `/api/Addresss` and `/rest/order-history` (30 B, empty array). Both sides returned nothing, so the lengths matched. That is not a bypass.
- "Is enforced???" on `/rest/user/login` and `/rest/captcha/`: these are not access-controlled resources.

### Both agreed

Row 9 (`/rest/user/authentication-details/`), row 30 (`/rest/admin/application-configuration`) and the basket IDOR (rows 10 and 11).

---

## 4. Method notes

- Endpoints came from the Burp sitemap and from `main.js` plus its code-split chunks. Searching `main.js` alone misses paths, because the bundle is split.
- `/ftp` and `/metrics` were not in the bundle or the sitemap. I found them manually.
- The Burp sitemap (4xx responses shown) lists under `/api/`: Addresss, BasketItems, Cards, Challenges, Feedbacks, Products, Quantitys, Recycles, SecurityAnswers, SecurityQuestions, Users. Under `/rest/`: admin, basket, captcha, continue-code, deluxe-membership, languages, order-history, products, saveLoginIp, user, wallet.
- Found in the bundle but not tested: `/api/Hints`, `/api/SecurityAnswers`, `/rest/2fa/*`, `/rest/memories`, `/rest/track-order`, `/rest/passkey`, `/rest/user/change-password`, `/rest/user/reset-password`.
- Rows 19 and 20 (feedback POST and DELETE) were not tested, because each request needs a fresh captcha.
- My first run of row 8 (`/rest/user/whoami`) showed an empty object for every role. The endpoint reads the token from the cookie, not the Authorization header. I fixed the script and re-ran it rather than recording a false result.
- The script's body classifier mislabelled some responses. Rows 22, 33 and 35 were checked by reading the actual body.
