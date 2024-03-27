package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/calmdocs/appexit"
	"github.com/calmdocs/keyexchange"

	"github.com/gorilla/mux"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Flag variables
	killPID := flag.Int("pid", 0, "source process identifier (pid)") // -pid=7423
	authToken := flag.String("token", "", "authentication token")
	port := flag.Int("port", 0, "port")

	flag.Parse()

	if port == nil || *port == 0 {
		fmt.Println("Exiting.  Please provide port (e.g. -port=8080))")
		os.Exit(0)
	}

	if killPID == nil || *killPID == 0 {
		fmt.Println("Exiting.  Please run script with process id to monitor (e.g. -pid=1234)")
		os.Exit(0)
	}
	if authToken == nil || *authToken == "" {
		fmt.Println("Exiting.  Please provide authentication token (e.g. -token=abc123)")
		os.Exit(0)
	}

	// Exit when process with pid exits
	if killPID != nil && *killPID != 0 {
		fmt.Println("Exit when the process with the following pid exits:", *killPID)
		appexit.PID(ctx, cancel, killPID)
	}

	// Create keyexchangeStore and print public key to stdOut as PEM
	keyexchangeStore, err := keyexchange.New_Curve25519_SHA256_HKDF_AESGCM(
		*authToken,
	)
	if err != nil {
		panic(err)
	}
	pemString, err := keyexchangeStore.PublicKeyPEM()
	if err != nil {
		panic(err)
	}
	fmt.Println(pemString)

	// Create store
	s := NewStore(
		*authToken,
		keyexchangeStore,
		keyexchange.CurrentTimestamp(),
	)

	// Create mux router
	r := mux.NewRouter().StrictSlash(true)
	r.HandleFunc("/request", func(w http.ResponseWriter, r *http.Request) {

		// Local access only
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if ip != "127.0.0.1" {
			fmt.Println("remote access forbidden:", ip)
			w.WriteHeader(http.StatusForbidden)
			return
		}

		// Auth
		bearerToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearerToken != *authToken {
			fmt.Printf("auth failure (bearerToken: %s, authToken: %s)\n", bearerToken, *authToken)
			http.Error(w, "id error", http.StatusForbidden)
			return
		}

		// Get wsRequest
		var wsRequest WSRequest
		b, err := io.ReadAll(r.Body)
		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		err = s.keyexchangeStore.UnmarshalJSONAndDecryptFromJSONWithADCheck(
			b,
			&wsRequest,
			func(additionalData []byte) (bool, error) {

				// Only process new messages
				ok, i, err := keyexchange.AuthTimestamp(additionalData, s.additionalDataTimestamp)
				if err != nil {
					fmt.Println(err.Error())
					return false, err
				}
				if !ok {
					fmt.Println("auth timestamp failure")
					return false, nil
				}
				s.additionalDataTimestamp = i
				return true, nil
			},
		)
		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Process wsRequest
		err = s.wsHandleInput(r.Context(), wsRequest, w)
		if err != nil {
			fmt.Println(err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	})

	// Start item randomiser
	go s.StartRandomiser(ctx)

	// Create the first item
	s.newItem()

	// Create http server
	httpServer := http.Server{
		Handler: r,
		Addr:    fmt.Sprintf("%s:%d", "localhost", *port),
		//WriteTimeout: 15 * time.Second,
		//ReadTimeout:  15 * time.Second,
	}
	defer httpServer.Close()

	// Start http server
	err = httpServer.ListenAndServe()
	if err != nil {
		if !strings.Contains(err.Error(), "http: Server closed") {
			panic(err)
		}
	}
}

type Status struct {
	ID       int64
	Error    error
	Name     string
	Status   string
	Progress float64
}

type WSRequest struct {
	Type string
	ID   interface{}
	Data interface{}
}

type Store struct {
	sync.RWMutex

	m     map[int64]Status
	maxID int64

	authToken               string
	keyexchangeStore        *keyexchange.Store
	additionalDataTimestamp int64
}

func NewStore(
	authToken string,
	keyexchangeStore *keyexchange.Store,
	additionalDataTimestamp int64,
) *Store {
	return &Store{
		m:                       make(map[int64]Status),
		maxID:                   0,
		authToken:               authToken,
		keyexchangeStore:        keyexchangeStore,
		additionalDataTimestamp: additionalDataTimestamp,
	}
}

func (s *Store) StartRandomiser(parentCtx context.Context) {
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()

	ticker := time.NewTicker(1250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:

			// Randomise all items (every 1.25 seconds)
			s.randomiseAllItems()
		}
	}
}

func (s *Store) wsHandleInput(ctx context.Context, wsRequest WSRequest, w http.ResponseWriter) (err error) {

	// Handle message
	switch wsRequest.Type {

	case "ping":

		// Unmarshal inStatus
		var inStatus []Status
		err = json.Unmarshal([]byte(wsRequest.Data.(string)), &inStatus)
		if err != nil {
			return err
		}

		// Long poll until the local status does not match the inStatus
		m := []Status{}

		idleDuration := time.Second
		idleDelay := time.NewTimer(idleDuration)
		defer idleDelay.Stop()
		done := false
		for !done {
			done = true

			idleDelay.Reset(idleDuration)

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			m = []Status{}
			for _, wd := range s.m {
				wd = wd

				isClone := false
				for _, v := range inStatus {
					v = v
					switch {
					case v.ID != wd.ID:
					case v.Status != wd.Status:
					default:
						isClone = true
					}
				}
				if isClone {
					continue
				}
				m = append(m, wd)
			}

			// Retry if no updates to inStatus groups
			if len(inStatus) != 0 && len(m) == 0 {
				done = false

				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-idleDelay.C:
				}
				continue
			}
		}

		// Send local status
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		b, err := s.keyexchangeStore.EncodeJSONAndEncryptToJSON(
			m,
			keyexchange.CurrentTimestampBytes(),
		)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		if err != nil {
			return err
		}

	case "addItem":
		s.newItem()

	case "deleteItem":
		itemString, ok := wsRequest.ID.(string)
		if !ok {
			return fmt.Errorf("request identifier is not a string: %v", wsRequest.ID)
		}
		itemID, err := strconv.ParseInt(itemString, 10, 64)
		if err != nil {
			return err
		}
		ok = s.deleteItem(itemID)
		if !ok {
			return fmt.Errorf("item to delete does not exist: %d", itemID)
		}

	default:
		return fmt.Errorf("unrecognised inbound ws message: %#v", wsRequest)
	}
	return nil

}

func (s *Store) newItem() {
	s.Lock()
	defer s.Unlock()

	s.maxID += 1
	s.m[s.maxID] = Status{
		ID:       s.maxID,
		Error:    nil,
		Name:     fmt.Sprintf("entry %d", s.maxID),
		Status:   fmt.Sprintf("%.2f %%", float64(0)*100),
		Progress: 0,
	}
}

func (s *Store) deleteItem(itemID int64) bool {
	s.Lock()
	defer s.Unlock()

	_, ok := s.m[itemID]
	if !ok {
		return false
	}
	delete(s.m, itemID)
	return true
}

func (s *Store) randomiseAllItems() {
	s.Lock()
	defer s.Unlock()

	for _, sg := range s.m {
		sg = sg

		newProgress := rand.Float64()
		sg.Progress = newProgress
		sg.Status = fmt.Sprintf("%.2f %%", newProgress*100)
		s.m[sg.ID] = sg
	}
}
