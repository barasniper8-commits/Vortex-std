export default function handler(req, res) {
  res.setHeader('Content-Type', 'text/plain');
  res.status(200).send(process.env.APP_TARGET_URL);
}
