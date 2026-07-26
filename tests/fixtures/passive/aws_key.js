// Synthetic fixture — NOT a live credential
// Format-valid AWS access key for detector true-positive tests
// Shape: AKIA + 16 uppercase alnum (not the AWS docs EXAMPLE token)
const config = {
  region: "us-east-1",
  accessKeyId: "AKIAJFAKESECRET00001",
  endpoint: "https://example.com/api",
};
export default config;
