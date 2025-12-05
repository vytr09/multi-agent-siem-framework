export const API_BASE_URL = "http://localhost:8000";

export interface AgentStatus {
    extractor: string;
    rulegen: string;
    evaluator: string;
    attackgen: string;
}

export interface AgentDetail {
    name: string;
    description: string;
    model: string;
    type: string;
    capabilities: string[];
}

export interface AgentsResponse {
    status: AgentStatus;
    details: Record<string, AgentDetail>;
}

export interface SystemMetrics {
    system_status: string;
    active_agents: AgentStatus;
    rules_generated: number;
    detection_rate: number;
    attacks_launched: number;
}

export const api = {
    async getHealth() {
        const res = await fetch(`${API_BASE_URL}/health`);
        return res.json();
    },

    async getAgents(): Promise<AgentsResponse> {
        const res = await fetch(`${API_BASE_URL}/agents/`);
        return res.json();
    },

    async getMetrics() {
        const res = await fetch(`${API_BASE_URL}/metrics/`);
        return res.json();
    },

    async startPipeline(data: any) {
        const res = await fetch(`${API_BASE_URL}/agents/run`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(data),
        });
        return res.json();
    },

    async runAgent(agentName: string, input: any) {
        const res = await fetch(`${API_BASE_URL}/agents/${agentName}/run`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(input),
        });
        return res.json();
    },

    async getRules() {
        const res = await fetch(`${API_BASE_URL}/rules/`);
        return res.json();
    },

    async getLogs(limit: number = 100) {
        const res = await fetch(`${API_BASE_URL}/logs/?limit=${limit}`);
        return res.json();
    },

    async getActivity(limit: number = 5) {
        const res = await fetch(`${API_BASE_URL}/metrics/activity?limit=${limit}`);
        return res.json();
    },

    async getLatestAttack() {
        const res = await fetch(`${API_BASE_URL}/metrics/latest_attack`);
        return res.json();
    },

    async getAttacks() {
        const res = await fetch(`${API_BASE_URL}/attacks/`);
        return res.json();
    },

    async getSettings() {
        const res = await fetch(`${API_BASE_URL}/settings/`);
        return res.json();
    },

    async updateSettings(payload: any) {
        const res = await fetch(`${API_BASE_URL}/settings/`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        return res.json();
    }
};
