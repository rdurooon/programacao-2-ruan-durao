const z = require('zod');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(bodyParser.json());
const emailValidationSchema = z.object({
  email: z.string().email({ required_error: 'Email is required.', invalid_type_error: 'Email is invalid.' }),
  confirmEmail: z.string().email({ required_error: 'Email confirmation is required.', invalid_type_error: 'Email confirmation is invalid.' })
}).refine(data => data.email === data.confirmEmail, {
  message: 'Emails must match.',
  path: ['email', 'confirmEmail'],
});
app.post('/validateEmails', (req, res) => {
  try {
    emailValidationSchema.parse(req.body);
    res.send({ message: 'Emails validated successfully!' });
  } catch (error) {
    res.status(400).send(error);
  }
});
app.listen(3000, () => console.log('Server running on port 3000'));