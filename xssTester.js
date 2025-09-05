(async function xssTester() {
  // Sample payload to inject
  const payload = "<script>alert('XSS')</script>";

  // Parameters to test - you can expand this as needed
  const testParams = ['input1', 'comment', 'search', 'msg'];

  // Base URL for testing (change this to your target)
  const baseUrl = window.location.origin + window.location.pathname;

  const vulnerableEndpoints = [];

  for (const param of testParams) {
    try {
      // Construct URL with payload injected in param
      const testUrl = `${baseUrl}?${param}=${encodeURIComponent(payload)}`;

      // Fetch page with injected param
      const response = await fetch(testUrl);
      const text = await response.text();

      // Simple response analysis: check if payload is present in returned HTML (reflected)
      if (text.includes(payload)) {
        vulnerableEndpoints.push(testUrl);
        console.log(`Possible reflected XSS detected at: ${testUrl}`);
      }

      // Create a DOM parser to detect payload in DOM (simulate DOM inspection)
      const parser = new DOMParser();
      const doc = parser.parseFromString(text, 'text/html');
      if (doc.body.innerHTML.includes(payload)) {
        vulnerableEndpoints.push(testUrl);
        console.log(`Payload found in DOM for: ${testUrl}`);
      }

    } catch (error) {
      console.error("Error testing param", param, error);
    }
  }

  if (vulnerableEndpoints.length) {
    console.log("Summary of vulnerable URLs detected:");
    vulnerableEndpoints.forEach(url => console.log(url));
  } else {
    console.log("No reflections of payload found - no reflected XSS detected in tested parameters.");
  }

  console.log("\n--- XSS Prevention Tips ---");
  console.log("* Sanitize and encode all user inputs on server and client side.");
  console.log("* Use Content Security Policy (CSP) headers.");
  console.log("* Avoid directly injecting untrusted data into HTML without escaping.");
  console.log("* Use frameworks and libraries that auto-escape outputs.");

})();
