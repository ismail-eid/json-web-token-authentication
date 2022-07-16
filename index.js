const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
const corsOptions = {
  origin: 'http://localhost:8081'
}
app.use(cors(corsOptions));
// parse requests for content-type - application/json
app.use(bodyParser.json());
// parse requests for content-type - application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }))
// simple route
app.get('/', (req, res) => {
  res.send({  message: 'Welcome to bezkoder application.'})
})
// set port, listen for requests
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`)
})