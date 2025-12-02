"""#05 Injection
- Secure code Java"""

String username = request.getParameter("username");

Statement stmt = connection.createStatement();
String query = "SELECT * FROM users WHERE username = '" + username + "'";
ResultSet rs = stmt.executeQuery(query);
