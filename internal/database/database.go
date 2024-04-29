package database

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type DB struct {
    path string
    mux *sync.RWMutex
}

type Chirp struct {
    ID int `json:"id"`
    Body string `json:"body"`
}

type User struct {
    ID int `json:"id"`
    Email string `json:"email"`
    Password []byte `json:"password"`
}

type CleanUser struct {
    ID int `json:"id"`
    Email string `json:"email"`
}

type DBStructure struct {
    Chirps map[int]Chirp `json:"chirps"`
    Users map[int]User `json:"users"`
}

func NewDB(path string) (*DB, error) {
    db := &DB{
        path: path,
        mux: &sync.RWMutex{},
    }

    err := db.ensureDB()

    if err != nil {
        return nil, err
    } 

    return db, nil
}

func (db *DB) GetUser(email string, password string) (CleanUser, error) {
    dbdata, err := db.loadDB()

    if err != nil {
        return CleanUser{}, err
    }

    var user CleanUser

    for i, u := range dbdata.Users {
        err := bcrypt.CompareHashAndPassword(u.Password, []byte(password))
        
        if err != nil {
            continue
        }

        if u.Email == email {
            user = CleanUser{ ID: dbdata.Users[i].ID, Email: dbdata.Users[i].Email }
            break
        }
    }

    if user.Email == "" {
        return CleanUser{}, errors.New("no user found") 
    }

    return user, nil
}

func (db *DB) UpdateUser(u User) (CleanUser, error) {
    dbdata, err := db.loadDB()

    if err != nil {
        return CleanUser{}, err
    }
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password), 14) 

    if err != nil {
        return CleanUser{}, errors.New("error updating user")
    }

    user := User{ ID: u.ID, Email: u.Email, Password: hashedPassword }
    cleanuser := CleanUser{ ID: u.ID, Email: u.Email }

    dbdata.Users[u.ID] = user
    err = db.writeDB(dbdata)

    if err != nil {
        return CleanUser{}, errors.New("error updating user")
    }

    return cleanuser, nil
}

func (db *DB) CreateUser(email string, password string) (CleanUser, error) {
    dbdata, err := db.loadDB()

    if err != nil {
        return CleanUser{}, err
    }
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 14) 

    if err != nil {
        return CleanUser{}, errors.New("error saving user")
    }

    userID := len(dbdata.Users) + 1
    user := User{ ID: userID, Email: email, Password: hashedPassword }
    cleanuser := CleanUser{ ID: userID, Email: email }

    dbdata.Users[userID] = user
    err = db.writeDB(dbdata)

    if err != nil {
        return CleanUser{}, errors.New("error saving user")
    }

    return cleanuser, nil
}

func (db *DB) CreateChirp(body string) (Chirp, error) {
    dbdata, err := db.loadDB()

    if err != nil {
        return Chirp{}, err
    }

    chirpID := len(dbdata.Chirps) + 1
    chirp := Chirp{ ID: chirpID, Body: body }

    dbdata.Chirps[chirpID] = chirp
    err = db.writeDB(dbdata)

    if err != nil {
        return Chirp{}, errors.New("error saving chirp")
    }

    return chirp, nil
}

func (db *DB) GetChirp(id int) (Chirp, error) {
    dbdata, err := db.loadDB()

    if err != nil {
        return Chirp{}, err
    }

    chirp, ok := dbdata.Chirps[id]

    if ok {
        return chirp, nil
    } 

    return Chirp{}, errors.New("chirp not found")
}

func (db *DB) GetChirps() ([]Chirp, error) {
    dbdata, err := db.loadDB()

    if err != nil {
        return nil, err
    }

    chirps := []Chirp{}

    for _, c := range dbdata.Chirps {
        chirps = append(chirps, c)
    }

    sort.Slice(chirps, func(i, j int) bool { return chirps[i].ID < chirps[j].ID })

    return chirps, nil
}

func (db *DB) ensureDB() error {
    db.mux.RLock()
    _, err := os.ReadFile(db.path)
    db.mux.RUnlock()

    if err != nil {
        if os.IsNotExist(err) {
            d := DBStructure{
                Chirps: map[int]Chirp{},
                Users: map[int]User{},
            }
            dat, err := json.Marshal(d)

            if err != nil {
                return errors.New("error marshalling data")
            }

            db.mux.Lock()
            err = os.WriteFile(db.path, dat, 0666)
            db.mux.Unlock()

            if err != nil {
                return errors.New("error saving db")
            }

            return nil
        }

        return errors.New("error creating db")
    }

    return nil
}

func (db *DB) writeDB(data DBStructure) error {
    err := db.ensureDB()

    if err != nil {
        return errors.New("error creating db")
    }

    d, err := json.Marshal(data)

    if err != nil {
        return errors.New("error marshalling data")
    }
    
    db.mux.Lock()
    err = os.WriteFile(db.path, d, 0666)
    db.mux.Unlock()

    if err != nil {
        return errors.New("error saving db")
    }

    return nil
}

func (db *DB) loadDB() (DBStructure, error) {
    err := db.ensureDB()

    if err != nil {
        return DBStructure{}, errors.New("error creating db")
    }

    db.mux.RLock()
    rawdat, err := os.ReadFile(db.path)
    db.mux.RUnlock()

    if err != nil {
        return DBStructure{}, errors.New("error reading file")
    }
    
    dat := DBStructure{}
    err = json.Unmarshal(rawdat, &dat)

    if err != nil {
        return DBStructure{}, errors.New("error unmarshaling json")
    }

    if dat.Chirps == nil {
        dat.Chirps = make(map[int]Chirp)
    }

    if dat.Users == nil {
        dat.Users = make(map[int]User)
    }


    return dat, nil
}
