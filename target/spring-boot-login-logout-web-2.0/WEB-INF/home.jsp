<html>
<head>
<title>Home Page</title>
</head>
<body>
	
	${message} User: ${pageContext.request.userPrincipal.name}
Hi<%session.getAttribute("name"); %>
<a href="javascript:formSubmit()"> Logout</a>

				<form action="<%=request.getContextPath()%>/logout" method="POST" id="logoutForm">
				
				<!-- This is added since csrf protection is enabled by default in spring security -->
				<input type="hidden" name="${_csrf.parameterName}"
				value="${_csrf.token}" />
				</form>
				 <script>
					function formSubmit() {
						document.getElementById("logoutForm").submit();
					}
				</script>
</body>
</html>