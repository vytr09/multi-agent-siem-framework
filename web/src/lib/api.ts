export const API_BASE_URL = "http://localhost:8000";

export interface AgentStatus {
    extractor: string;
    rulegen: string;
    evaluator: string;
    attackgen: string;
    pipeline?: string;
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
    },

    // Provider Manager APIs
    async getProviders() {
        const res = await fetch(`${API_BASE_URL}/providers/`);
        return res.json();
    },

    async updateProviders(payload: any) {
        const res = await fetch(`${API_BASE_URL}/providers/`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        return res.json();
    },

    async setActiveProvider(providerName: string) {
        const res = await fetch(`${API_BASE_URL}/providers/active`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ provider_name: providerName }),
        });
        if (!res.ok) throw new Error("Failed to set active provider");
        return res.json();
    },

    async reloadAgents() {
        const res = await fetch(`${API_BASE_URL}/providers/reload`, {
            method: "POST",
        });
        if (!res.ok) throw new Error("Failed to reload agents");
        return res.json();
    },

    async uploadFile(file: File) {
        const formData = new FormData()
        formData.append("file", file)
        const res = await fetch(`${API_BASE_URL}/files/upload`, {
            method: "POST",
            body: formData,
        })
        if (!res.ok) throw new Error("Failed to upload file")
        return res.json()
    },

    async runPipelineFromFile(filename: string, force: boolean = false) {
        const res = await fetch(`${API_BASE_URL}/agents/run_file`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ filename, force })
        })
        if (!res.ok) throw new Error("Failed to run pipeline")
        return res.json()
    },

    async getFiles() {
        const res = await fetch(`${API_BASE_URL}/files/`)
        if (!res.ok) throw new Error("Failed to fetch files")
        return res.json()
    },

    async getFileContent(filename: string) {
        const res = await fetch(`${API_BASE_URL}/files/content/${filename}`)
        if (!res.ok) throw new Error("Failed to fetch file content")
        return res.json()
    },

    async getKnowledgeStats() {
        const res = await fetch(`${API_BASE_URL}/knowledge/stats`)
        if (!res.ok) throw new Error("Failed to fetch knowledge stats")
        return res.json()
    },

    async searchKnowledge(query: string, type: string = "all") {
        const res = await fetch(`${API_BASE_URL}/knowledge/search?query=${encodeURIComponent(query)}&type=${type}`)
        if (!res.ok) throw new Error("Failed to search knowledge base")
        return res.json()
    },

    async getPipelineResult() {
        const res = await fetch(`${API_BASE_URL}/pipeline/result`)
        if (!res.ok) throw new Error("Failed to fetch pipeline result")
        return res.json()
    }
};
