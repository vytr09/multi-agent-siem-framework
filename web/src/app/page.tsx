"use client"

import { useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Activity, Shield, Zap, Target, Play, AlertTriangle, CheckCircle, RefreshCw, FileText, Clock, Search, Eye } from "lucide-react"
import { api, type AgentStatus, type SystemMetrics } from "@/lib/api"
import { useToast } from "@/components/ui/toast-notification"
import { FileUpload } from "@/components/dashboard/file-upload"
import { PipelineVisualizer } from "@/components/dashboard/pipeline-visualizer"
import { Checkbox } from "@/components/ui/checkbox"
import { formatDistanceToNow } from "date-fns"
import { FileViewerModal } from "@/components/dashboard/file-viewer-modal"
import { PipelineSummary } from "@/components/dashboard/pipeline-summary"
import { PipelineResultsModal } from "@/components/dashboard/pipeline-results-modal"
import { useNotifications } from "@/contexts/notification-context"

export default function Workbench() {
  const { showToast } = useToast()
  const [activeCases, setActiveCases] = useState<any[]>([])
  const [pipelineState, setPipelineState] = useState(0) // 0=Idle, 1=Ingest, 2=Extract, 3=RuleGen, 4=Verify
  const [loading, setLoading] = useState(true)
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null)

  const [viewingFile, setViewingFile] = useState<string | null>(null)
  const [forceAnalyze, setForceAnalyze] = useState(false)
  const [pipelineResult, setPipelineResult] = useState<any>(null)
  const [showResultsModal, setShowResultsModal] = useState(false)

  const { addNotification } = useNotifications()

  const fetchData = async () => {
    try {
      setLoading(true)
      const files = await api.getFiles()
      setActiveCases(files)
    } catch (error) {
      console.error("Failed to fetch data:", error)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [pipelineState]) // Refresh when pipeline state changes

  const handleUploadComplete = () => {
    showToast("File uploaded successfully. New Case created.", "success")
    fetchData()
  }
  const handleRunPipeline = async (caseId: string) => {
    setSelectedCaseId(caseId)
    setPipelineState(1)
    showToast(`Starting investigation for Case ${caseId.substring(0, 8)}...`, "info")
    addNotification("Investigation Started", `Analysis started for case ${caseId.substring(0, 8)}...`, "info")

    try {
      // Start the pipeline
      await api.runPipelineFromFile(caseId, forceAnalyze);
      setPipelineState(2) // Move to extraction/running visual state

      // Poll for completion
      const interval = setInterval(async () => {
        try {
          const agents = await api.getAgents();
          const status = agents.status.pipeline;

          console.log("Pipeline Status:", status);

          if (status === 'completed') {
            clearInterval(interval);
            setPipelineState(4);
            showToast("Investigation completed successfully.", "success");
            addNotification("Investigation Complete", `Analysis for case ${caseId.substring(0, 8)} finished successfully.`, "success")

            // Fetch the pipeline result
            try {
              const result = await api.getPipelineResult();
              setPipelineResult(result);
            } catch (e) {
              console.error("Failed to fetch pipeline result:", e);
            }
          } else if (status === 'error') {
            clearInterval(interval);
            setPipelineState(0);
            showToast("Investigation failed. Check backend logs.", "error");
            addNotification("Investigation Failed", `Analysis for case ${caseId.substring(0, 8)} failed.`, "error")
          } else if (status === 'running') {
            // Keep spinning
            setPipelineState((prev) => prev === 2 ? 3 : 2);
          }
        } catch (e) {
          console.error("Polling error:", e);
        }
      }, 1000);

    } catch (error) {
      console.error("Pipeline failed to start:", error);
      setPipelineState(0); // Reset or Error state
      showToast("Failed to start investigation.", "error");
      addNotification("Launch Failed", "Could not start the investigation pipeline.", "error")
    }
  }

  return (
    <div className="space-y-8 max-w-7xl mx-auto">
      {/* Header Section */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold font-heading text-foreground">Analyst Workbench</h1>
          <p className="text-muted-foreground mt-1">
            Manage CTI reports, investigate threats, and orchestrate agent pipelines.
          </p>
        </div>
        <div className="flex gap-3">
          <Button variant="outline" onClick={fetchData}>
            <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
            Refresh Cases
          </Button>
        </div>
      </div>

      {/* Pipeline Status */}
      <Card className="border-primary/20 bg-primary/5">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-primary" />
            Active Investigation Pipeline
          </CardTitle>
        </CardHeader>
        <CardContent>
          {selectedCaseId ? (
            <div className="space-y-4">
              <div className="flex items-center justify-between text-sm">
                <span className="font-medium">Case ID: <span className="font-mono text-muted-foreground">{selectedCaseId}</span></span>
                <Badge variant={pipelineState === 4 ? "default" : "secondary"}>
                  {pipelineState === 0 ? "Idle" : pipelineState === 4 ? "Completed" : "Processing..."}
                </Badge>
              </div>
              <PipelineVisualizer currentStage={pipelineState} />

              {/* Show summary when completed */}
              {pipelineState === 4 && (
                <PipelineSummary
                  result={pipelineResult}
                  onViewDetails={() => setShowResultsModal(true)}
                />
              )}
            </div>
          ) : (
            <div className="text-center py-8 text-muted-foreground">
              <p>No active investigation. Select a case or upload a report to start.</p>
            </div>
          )}
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column: Upload & New Case */}
        <div className="lg:col-span-1 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>New Investigation</CardTitle>
              <CardDescription>Upload a CTI report (PDF/TXT) to start.</CardDescription>
            </CardHeader>
            <CardContent>
              <FileUpload onUploadComplete={handleUploadComplete} />
            </CardContent>
          </Card>
        </div>

        {/* Right Column: Case Management */}
        <div className="lg:col-span-2 space-y-6">
          <Card className="h-full">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span>Case Files</span>
                <div className="flex items-center gap-4">
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="force-analyze"
                      checked={forceAnalyze}
                      onCheckedChange={(checked) => setForceAnalyze(checked as boolean)}
                    />
                    <label
                      htmlFor="force-analyze"
                      className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 text-muted-foreground"
                    >
                      Force Re-analyze
                    </label>
                  </div>
                  <div className="relative w-64">
                    <Search className="absolute left-2 top-2.5 h-4 w-4 text-muted-foreground" />
                    <input
                      type="text"
                      placeholder="Search cases..."
                      className="w-full rounded-md border border-input bg-background pl-8 py-2 text-sm ring-offset-background placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                    />
                  </div>
                </div>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-1">
                {activeCases.length === 0 ? (
                  <div className="text-center py-10 text-muted-foreground">
                    <FileText className="h-10 w-10 mx-auto mb-3 opacity-20" />
                    <p>No cases found.</p>
                  </div>
                ) : (
                  activeCases.map((file) => (
                    <div key={file.filename} className="group flex items-center justify-between p-4 rounded-lg hover:bg-muted/50 transition-colors border border-transparent hover:border-border">
                      <div className="flex items-start gap-3">
                        <div className="p-2 rounded-md bg-muted text-muted-foreground group-hover:text-primary group-hover:bg-primary/10 transition-colors">
                          <FileText className="h-5 w-5" />
                        </div>
                        <div>
                          <p className="font-medium text-foreground truncate max-w-[300px]" title={file.filename}>
                            {file.filename.replace(/^\d{8}_\d{6}_/, '')}
                          </p>
                          <div className="flex items-center gap-2 text-xs text-muted-foreground mt-1">
                            <Clock className="h-3 w-3" />
                            <span>{new Date(file.modified).toLocaleDateString()}</span>
                            <span>•</span>
                            <span>{(file.size / 1024).toFixed(1)} KB</span>
                          </div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                        <Button size="sm" variant="ghost" className="h-8 w-8 p-0" onClick={() => setViewingFile(file.filename)}>
                          <Eye className="h-4 w-4 text-muted-foreground hover:text-foreground" />
                        </Button>
                        <Button size="sm" variant="secondary" onClick={() => handleRunPipeline(file.filename)}>
                          <Play className="h-3 w-3 mr-1" /> Analyze
                        </Button>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      <FileViewerModal
        isOpen={!!viewingFile}
        filename={viewingFile}
        onClose={() => setViewingFile(null)}
      />

      <PipelineResultsModal
        isOpen={showResultsModal}
        onClose={() => setShowResultsModal(false)}
        result={pipelineResult}
      />
    </div>
  )
}
