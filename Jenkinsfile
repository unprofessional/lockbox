// lockbox CI - builds an installable macOS artifact (.dmg) from a Tauri v2 project.
//
// Assumptions (see README notes from CI setup):
// - Jenkins agent with label 'macbook' = mads's MacBook Pro, running macOS,
//   with Xcode CLT, Rust (stable), and Node 22+ installed for the agent user.
// - Job is a plain pipeline (CpsScmFlowDefinition); the branch to build is
//   selected in job SCM config (refspec), NOT here. No env.BRANCH_NAME in a
//   plain pipeline - PIPE_BRANCH is derived from GIT_BRANCH below.
// - Artifact is unsigned/ad-hoc signed (no notarization - brief non-goal).

pipeline {
  agent { label 'macbook' }

  environment {
    // Makes tauri's bundle_dmg.sh skip its Finder AppleScript layout step,
    // which times out without Automation permission (no GUI session needed).
    CI = 'true'
  }

  options {
    disableConcurrentBuilds()
    timestamps()
    skipDefaultCheckout(true)
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
        script {
          env.PIPE_BRANCH = sh(returnStdout: true, script: "printf %s '${env.GIT_BRANCH}' | sed 's#^origin/##'").trim()
          env.COMMIT = sh(returnStdout: true, script: 'git rev-parse HEAD').trim()
          echo "Building ${env.PIPE_BRANCH} @ ${env.COMMIT}"
        }
      }
    }

    stage('Toolchain check') {
      steps {
        sh label: 'Verify build toolchain', script: '''
          set -eu
          rustc --version
          cargo --version
          node --version
          npm --version
          xcodebuild -version || xcode-select -p
        '''
      }
    }

    stage('Install deps') {
      steps {
        sh label: 'npm ci', script: '''
          set -eu
          npm ci
        '''
      }
    }

    stage('Test') {
      steps {
        sh label: 'Rust tests', script: '''
          set -eu
          cargo test --manifest-path src-tauri/Cargo.toml --locked
        '''
      }
    }

    stage('Audit') {
      steps {
        sh label: 'Surface check + cargo audit', script: '''
          set -eu
          sh scripts/check-surface.sh
          cargo audit --file src-tauri/Cargo.lock
        '''
      }
    }

    stage('Build .dmg') {
      steps {
        sh label: 'Tauri build (dmg bundle)', script: '''
          set -eu
          npm run tauri build -- --bundles dmg
        '''
      }
    }

    stage('Archive artifact') {
      steps {
        script {
          def dmg = sh(returnStdout: true, script: 'ls src-tauri/target/release/bundle/dmg/*.dmg | head -n1').trim()
          env.DMG_PATH = dmg
          echo "Artifact: ${dmg}"
          // FAIL the build if the dmg somehow doesn't exist (green != artifact).
          sh(script: "test -f '${dmg}' && echo 'PASS dmg exists'")
        }
        archiveArtifacts artifacts: 'src-tauri/target/release/bundle/dmg/*.dmg', fingerprint: true, onlyIfSuccessful: true
      }
    }
  }

  post {
    success {
      echo "PASS lockbox ${env.PIPE_BRANCH} @ ${env.COMMIT} - dmg: ${env.DMG_PATH}"
    }
    failure {
      echo "FAIL lockbox ${env.PIPE_BRANCH} @ ${env.COMMIT}"
    }
    // NOTE: no cleanWs on purpose - src-tauri/target acts as the cargo build
    // cache between runs. If the workspace ever gets poisoned, wipe it manually.
  }
}
