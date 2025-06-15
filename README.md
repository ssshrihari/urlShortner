# TinyURL - URL Shortener

A simple, fast, and elegant URL shortener built with Node.js and Express.

## Features

- 🔗 **Shorten URLs**: Convert long URLs into short, shareable links
- 🎨 **Custom Short Codes**: Create personalized short URLs
- 📊 **Click Analytics**: Track clicks and view statistics
- 📱 **Responsive Design**: Works perfectly on all devices
- ⚡ **Fast & Lightweight**: Minimal dependencies, maximum performance
- 🔒 **URL Validation**: Ensures only valid URLs are shortened

## Demo
![Screenshot 2025-06-15 at 1 46 07 PM](https://github.com/user-attachments/assets/4ac94d4a-1274-454c-930c-11ad1de1fc1d)


## Quick Start

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/tinyurl-shortener.git
   cd tinyurl-shortener
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```

3. **Start the server**
   ```bash
   npm start
   ```

4. **Open your browser**
   Visit `http://localhost:3000`

### Development Mode

To run in development mode with auto-restart:

```bash
npm run dev
```

## API Endpoints

### POST /api/shorten
Shorten a URL

**Request Body:**
```json
{
  "url": "https://example.com/very/long/url",
  "customCode": "optional-custom-code"
}
```

**Response:**
```json
{
  "originalUrl": "https://example.com/very/long/url",
  "shortUrl": "http://localhost:3000/abc123",
  "shortCode": "abc123",
  "createdAt": "2024-01-15T10:30:00.000Z"
}
```

### GET /api/stats/:code
Get statistics for a short URL

**Response:**
```json
{
  "shortCode": "abc123",
  "originalUrl": "https://example.com/very/long/url",
  "createdAt": "2024-01-15T10:30:00.000Z",
  "totalClicks": 42,
  "recentClicks": [...]
}
```

### GET /api/urls
Get all shortened URLs (admin endpoint)

### GET /:code
Redirect to the original URL

## Deployment

### Heroku

1. **Create a Heroku app**
   ```bash
   heroku create your-app-name
   ```

2. **Deploy**
   ```bash
   git push heroku main
   ```

### Vercel

1. **Install Vercel CLI**
   ```bash
   npm i -g vercel
   ```

2. **Deploy**
   ```bash
   vercel
   ```

### Railway

1. **Connect your GitHub repo to Railway**
2. **Deploy automatically on push**

### Docker

1. **Build the image**
   ```bash
   docker build -t tinyurl-shortener .
   ```

2. **Run the container**
   ```bash
   docker run -p 3000:3000 tinyurl-shortener
   ```

## Environment Variables

- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Environment (development/production)

## File Structure

```
tinyurl-shortener/
├── server.js          # Main server file
├── package.json       # Dependencies and scripts
├── README.md          # This file
├── public/
│   └── index.html     # Frontend interface
└── .gitignore         # Git ignore rules
```

## Features Explanation

### URL Shortening
- Generates 6-character random codes
- Validates URLs before shortening
- Prevents duplicate custom codes

### Analytics
- Tracks click count per URL
- Records timestamps and basic metadata
- Provides stats API endpoint

### Frontend
- Modern, responsive design
- Real-time URL validation
- Copy-to-clipboard functionality
- Custom code toggle

## Customization

### Changing Short Code Length
In `server.js`, modify the `generateShortCode()` function:

```javascript
function generateShortCode() {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let result = '';
  for (let i = 0; i < 8; i++) { // Change 6 to 8 for longer codes
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}
```

### Adding Database Support
Replace the in-memory storage with a database:

```javascript
// Replace Map with database queries
const urlDatabase = new Map(); // Replace with DB connection
```

Popular options:
- **MongoDB** with Mongoose
- **PostgreSQL** with Sequelize
- **Redis** for caching

### Custom Domain
Update the short URL generation to use your domain:

```javascript
const shortUrl = `https://yourdomain.com/${shortCode}`;
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


## Support

If you found this project helpful, please give it a ⭐ on GitHub!

## Acknowledgments

- Built with Express.js
- Styled with modern CSS
- Inspired by bit.ly and TinyURL
# urlShortner
