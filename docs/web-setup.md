# Web Dashboard Setup

This guide covers web-specific setup and usage for the THREATWISE dashboard.

For backend installation, see [INSTALLATION.md](../INSTALLATION.md).

---

## Frontend Setup

The dashboard is a Next.js application located in the `web/` directory.

### 1. Install Dependencies

```bash
cd web
npm install
```

**Expected time**: 1-2 minutes

### 2. Environment Configuration

Create `web/.env.local`:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

**Optional variables:**
```env
NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws
NEXT_PUBLIC_ENABLE_ANALYTICS=false
```

### 3. Start Development Server

```bash
npm run dev
```

Dashboard will be available at `http://localhost:3000`

---

## Dashboard Features

### Overview Page

- **Active Agents**: Real-time agent status (4/4 when all ready)
- **Latest Detection**: Shows most recent pipeline result
- **System Metrics**: TTP extraction count, rule generation stats
- **Recent Logs**: Live system log stream

### Agents Page

Detailed status and configuration for each agent:
- Extractor Agent
- RuleGen Agent
- AttackGen Agent
- Evaluator Agent

### Rules Page

Browse generated Sigma rules with:
- Syntax highlighting
- SPL conversion preview
- Quality scores
- Associated TTPs

### Attacks Page

View attack simulation history:
- Generated commands
- Execution status
- SIEM detection results

### Logs Page

Filterable system logs with levels: DEBUG, INFO, WARNING, ERROR

---

## Using the Dashboard

### Running a Pipeline

**Method 1: Quick Run**
1. Click **"Run Pipeline"** button (top right)
2. Uses default sample CTI report
3. Full workflow executes automatically

**Method 2: Custom Report**
1. Navigate to Pipeline page
2. Paste CTI report content
3. Configure options (optional)
4. Click **"Execute Pipeline"**

### Pipeline Execution Flow

```
1. Extraction    → Extract TTPs from report
2. Rule Gen      → Generate Sigma rules
3. Attack Gen    → Create attack commands
4. Verification  → Execute on sandbox + SIEM query
5. Evaluation    → Score quality + provide feedback
```

**Progress tracking**: Real-time updates via WebSocket

### Viewing Results

**Inline Summary:**
- Appears on completion
- Shows: TTPs extracted, rules generated, detection rate

**Detailed Modal:**
- Click "View Details" on any result
- Includes:
  - Full TTP list with confidence scores
  - Generated rules (Sigma + SPL)
  - Attack commands executed
  - SIEM verification status
  - Quality scores breakdown

---

## Production Build

### Build for Production

```bash
cd web
npm run build
```

### Run Production Server

```bash
npm start
```

Alternatively, deploy to Vercel/Netlify:

```bash
# Vercel
npm install -g vercel
vercel deploy

# Environment variables must be set in Vercel dashboard
```

---

## Troubleshooting

### Dashboard shows "API Unavailable"

**Check backend:**
```bash
# Backend should be running
curl http://localhost:8000/health

# If not running
cd multi-agent-siem-framework
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

### "Run Pipeline" button does nothing

**Open browser console** (F12):
- Look for CORS errors → Backend needs `allow_origins` config
- Check network tab for failed requests
- Verify WebSocket connection established

### Empty agent status (0/4)

Backend agents not initialized:
```bash
# Check backend logs
tail -f logs/system.log

# Restart backend
# Ctrl+C then re-run uvicorn
```

### Logs page empty

**Verify log file:**
```bash
ls -la logs/system.log

# If missing
mkdir -p logs
touch logs/system.log

# Restart backend
```

### Detection result shows "MISSED"

Not a dashboard issue. Check:
1. Attack executed successfully (check SSH logs)
2. Splunk indexed the event (check SIEM)
3. Rule syntax correct (test manually in Splunk)

See [troubleshooting.md](troubleshooting.md) for detailed debugging.

---

## Development

### Project Structure

```
web/
├── src/
│   ├── app/              # Next.js 14 app router
│   ├── components/       # React components
│   │   ├── ui/          # shadcn/ui components
│   │   └── ...          # Custom components
│   └── lib/
│       └── api.ts       # API client
├── public/              # Static assets
└── package.json
```

### Adding New Features

**Create new API endpoint integration:**

```typescript
// src/lib/api.ts
export async function getCustomData() {
  const response = await fetch(`${API_URL}/api/custom`);
  return response.json();
}
```

**Add new page:**

```bash
# Create route
mkdir -p src/app/custom
touch src/app/custom/page.tsx
```

### UI Components

Dashboard uses [shadcn/ui](https://ui.shadcn.com/):

```bash
# Add new component
npx shadcn-ui@latest add button
```

---

## Configuration Reference

### API Client Settings

Edit `src/lib/api.ts`:

```typescript
const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
const WS_URL = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/ws';
```

### Styling

Uses TailwindCSS + CSS variables for theming.

Theme config: `src/app/globals.css`

---

## Performance Tips

1. **Enable production mode**: `npm run build` before deployment
2. **Use WebSocket**: For real-time updates (lower latency)
3. **Pagination**: Enable for large rule/log lists
4. **Caching**: Next.js caches static pages automatically

---

For backend configuration, see [CONFIGURATION.md](../CONFIGURATION.md).  
For API endpoints, see [api-reference.md](api-reference.md).
