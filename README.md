# OAuth 2.0 Integration with Keycloak - C# MVC Application

This is a simple MVC web application demonstrating how to authenticate users using Keycloak and OAuth 2.0.

## Setup Instructions

##### 1. Clone the repository
    git clone https://github.com/Mcfearless314/SSD_week14

### 2. Set up Keycloak
    docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:21.1.0 start-dev

### 3. Create a client
1. Access Keycloak Admin Console at `http://localhost:8080/auth/admin`
2. Log in with the admin credentials (admin/admin)
3. Select the `master` realm
4. Open the sidebar and click on `Clients`
5. Click on `Create client`
6. Set the client ID (save this value for later)
7. Enable `Client authentication`
8. Set the redirect URI to: `http://localhost:5002/Home/Callback`
9. Save the client

### 4. Configure the application secrets
1. While still in the Keycloak Admin Console, navigate to the `Clients` section
2. Select the client you just created
3. Go to the `Credentials` tab
4. Copy the `Client Secret`
5. Open the project in your preferred IDE (Rider, VS)
6. Run the following commands in the terminal to set up user secrets for your application:

```bash
dotnet user-secrets init
dotnet user-secrets set "OAuth:ClientId" "your-client-id"
dotnet user-secrets set "OAuth:ClientSecret" "your-client-secret" 
```

### 6. Run the Application
```bash
dotnet run
```
The application will be available at `http://localhost:5002`. You can now authenticate using Keycloak.

### 7. Test the Application
1. Open your browser and navigate to `http://localhost:5002`
2. Click on the "Login" button
3. You will be redirected to the Keycloak login page
4. Enter your Keycloak credentials
5. After successful authentication, you will be redirected back to the application
