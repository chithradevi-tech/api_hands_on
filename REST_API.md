**1. what is REST API?**

REST API stands for Representational State Transfer Application Programming Interface.
A REST API is an application programming interface that follows Representational State Transfer principles — stateless, resource-based, and uses HTTP methods to access/manipulate data.

---

**2. Key Principles of REST?**

Client–Server Separation: UI and data storage are separated.

Statelessness: Every request from the client contains all info needed to process it. The server doesn’t keep session state.

Uniform Interface: Use standard HTTP methods (GET, POST, PUT, DELETE, PATCH).

Resource-Based: Everything (users, products, orders) is treated as a resource, identified by a URL.

Representation: Data can be sent/received in multiple formats (commonly JSON).

Cacheable: Responses can be cached to improve performance.

Layered System: Can have intermediaries (load balancers, proxies) without the client knowing.


| Method     | Purpose                           |
| ---------- | --------------------------------- |
| **GET**    | Retrieve resource(s)              |
| **POST**   | Create a new resource             |
| **PUT**    | Replace/Update an entire resource |
| **PATCH**  | Partially update a resource       |
| **DELETE** | Remove a resource                 |


**Advantages of REST APIs**

Simplicity (built on HTTP).

Platform and language independent.

Scalable (stateless).

Widely supported tools and libraries.

Easier to integrate with web/mobile apps.

**Disadvantages of REST APIs**

Statelessness means more data sent in each request.

No built-in security — must use HTTPS and tokens (OAuth/JWT).

Less efficient for very complex operations compared to protocols like gRPC.

<img width="1024" height="452" alt="Image" src="https://github.com/user-attachments/assets/acfc8e1b-4d88-4e60-a207-9766d114c0fc" />

---

**3. What is a Resource?**

A resource is an object or data entity exposed by an API, identified by a URI. Example: /users/123

---

**4. What does stateless mean in REST?**

Each request from client to server must contain all info needed to understand and process it. The server does not store client state between requests.

---

**5. Common Response Codes in REST APIs**

| Code                      | Meaning                              |
| ------------------------- | ------------------------------------ |
| 200 OK                    | Successful request                   |
| 201 Created               | Resource created successfully        |
| 204 No Content            | Successful but no data to return     |
| 400 Bad Request           | Invalid request syntax or parameters |
| 401 Unauthorized          | Missing/invalid authentication       |
| 403 Forbidden             | Not allowed                          |
| 404 Not Found             | Resource not found                   |
| 500 Internal Server Error | Server encountered error             |


---

**6. How do you secure a REST API?**

Use HTTPS to encrypt data in transit.

Implement authentication & authorization (OAuth2, JWT tokens, API keys).

Validate input and output.

Rate limiting & throttling.

Use CORS policies correctly.

---

**7. How do you handle versioning in REST APIs?**

URI versioning: /v1/users

Header-based versioning: Accept: application/vnd.company.v1+json

Query parameter versioning: ?version=1

---

**8. How do you handle errors in REST APIs?**

Use standard HTTP status codes.

Return structured error responses (JSON with error_code, message).

Provide clear error messages and documentation.

---

**9. How do you improve REST API performance?**

Caching (ETag, Last-Modified, Redis).

Pagination for large datasets.

Compression (gzip).

Load balancing.

Database optimization (indexes).

Async/background processing for heavy tasks.

---

**10. What’s the difference between synchronous and asynchronous REST calls?**

Synchronous: Client waits for server response before continuing.

Asynchronous: Server may respond later or send updates via callbacks or websockets.

---

**11. How do you document a REST API?**

Use OpenAPI/Swagger specs.

Provide examples of requests/responses.

Include authentication details, rate limits, and error codes.

---

**12. Example of a RESTful URL Design?**

/users (GET all users)

/users/{id} (GET user by id)

/users/{id}/orders (nested resource)

---

**13. What is the maximum payload size that can be sent in POST methods?**

Theoretically, there is no such maximum limit for payload size that can be sent in POST methods. However, payloads with larger sizes can consume larger bandwidth. Thus the server could take more time to proceed with the request.

---

**14. What is caching in the REST API?**

REST API stores a copy of a server response in a particular location of computer memory to retrieve the server response fast in the future. This method is temporary and called "catching."  

---

**15. What is AJAX?**

AJAX stands for  Asynchronous javascript and XML.

---

**16. What does the HEAD method in REST APIs do?**

The HEAD method is used to return the HTTP Header in read-only form and not the Body.

---

**17. What is a ‘Resource’?**

Resource’ is defined as an object of a type that includes image, HTML file, text data, and any type of dynamic data.

---

**18. Important aspects of RESTful web services implementation?**

ResourcesRequest 
Headers
Request Body
Response Body
Status codes

---

**19. GET vs POST**

| Feature           | **GET**                                       | **POST**                                |
| ----------------- | --------------------------------------------- | --------------------------------------- |
| **Purpose**       | Retrieve data from the server                 | Send data to the server (create/update) |
| **Data Location** | Data is appended to the URL as a query string | Data is sent in the HTTP request body   |


**Key Differences**

| Aspect               | **GET**                                      | **POST**                                       |
| -------------------- | -------------------------------------------- | ---------------------------------------------- |
| **Use Case**         | Reading/fetching data (safe & idempotent)    | Submitting forms, creating/updating resources  |
| **Visibility**       | Parameters visible in URL                    | Parameters hidden in body                      |
| **Size Limit**       | Limited by max URL length (few KB)           | Much larger, controlled by server settings     |
| **Caching**          | Cacheable by browsers and proxies by default | Not cacheable by default                       |
| **Bookmarkable**     | Yes (URL contains all parameters)            | No (data in body)                              |
| **Idempotency**      | Safe and idempotent                          | Not idempotent by default                      |
| **Effect on Server** | Should not change state                      | Changes or creates resources                   |
| **When Used**        | Search queries, filters, fetching resources  | Form submissions, file uploads, secure actions |


**Security Comparison**

| Security Factor         | **GET**                                                     | **POST**                                                                           |
| ----------------------- | ----------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Data Exposure**       | Data appears in URL, stored in browser history, server logs | Data sent in body, not shown in URL or logs (but can still be captured in transit) |
| **Encryption**          | Only secure if using HTTPS                                  | Only secure if using HTTPS                                                         |
| **CSRF Susceptibility** | Both susceptible unless protected                           | Both susceptible unless protected                                                  |
| **Password/Form Data**  | Should not send sensitive data via GET                      | Preferred for sensitive data with HTTPS                                            |
